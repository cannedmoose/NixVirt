import sys, uuid, lxml, libvirt, subprocess
from xmldiff import main as xmldiff

# Switch off annoying libvirt stderr messages
# https://stackoverflow.com/a/45543887
def libvirt_callback(userdata, err):
    pass
libvirt.registerErrorHandler(f=libvirt_callback, ctx=None)

class Session:
    def __init__(self,uri,verbose):
        self.conn = libvirt.open(uri)
        self.verbose = verbose
        self.tempDeactivated = set()
        self.postHooks = []

    def vreport(self,msg):
        if self.verbose:
            print (msg, file=sys.stderr)

    # These are all objects that were temporarily deactivated, that is, for reasons other than user request
    def _recordTempDeactivated(self,oc,uuid):
        self.tempDeactivated.add((oc.type,uuid))

    def _wasTempDeactivated(self,oc,uuid):
        return (oc.type,uuid) in self.tempDeactivated
    
    def addPostHook(self, hook):
        self.postHooks.append(hook)
    
    def executePostHooks(self):
        for hook in self.postHooks:
            subprocess.run(hook)

class ObjectConnection:
    def __init__(self,type,session):
        self.type = type
        self.session = session
        self.conn = session.conn

    def vreport(self,objid,msg):
        self.session.vreport(self.type + " " + str(uuid.UUID(bytes=objid)) + ": " + msg)

    def getAll(self):
        return map(lambda lvobj: VObject(self,lvobj), self._getAllLV())

    def _fromLVObject(self,lvobj):
        return VObject(self,lvobj) if lvobj else None

    def fromUUID(self,objid):
        return self._fromLVObject(self._lookupByUUID(objid))

    def fromUUIDOrNone(self,objid):
        try:
            return self.fromUUID(objid)
        except libvirt.libvirtError:
            return None

    def fromName(self,name):
        return self._fromLVObject(self._lookupByName(name))

    def _fromXML(self,defn):
        return self._fromLVObject(self._defineXML(defn))

    def _undefine(self,lvobj):
        lvobj.undefine()

    def _getDependents(self,obj):
        return []

    def _addReconnectHooks(self, obj):
        pass

    def _tempDeactivateDependents(self,obj):
        dependents = self._getDependents(obj)
        for dependent in dependents:
            dependent._deactivate(temp = True)

    def _recordTempDeactivated(self,objid):
        self.session._recordTempDeactivated(self,objid)

    def _wasTempDeactivated(self,objid):
        return self.session._wasTempDeactivated(self,objid)

    def fromDefinition(self,specDef):
        specDefXML = lxml.etree.fromstring(specDef)
        specUUID = uuid.UUID(specDefXML.find("uuid").text).bytes
        found = self.fromUUIDOrNone(specUUID)
        if found is not None:
            foundDef = found.descriptionXMLText()
            foundDefXML = lxml.etree.fromstring(foundDef)
            foundName = foundDefXML.find("name").text
            specName = specDefXML.find("name").text
            if foundName != specName:
                found.undefine()
            self.vreport(specUUID,"redefine")
            subject = self._fromXML(specDef)
            subjectDef = subject.descriptionXMLText()
            defchanged = self._hasDefinitionChanged(specDef,foundDef,subjectDef)
            self.vreport(specUUID,"changed" if defchanged else "unchanged")
            if defchanged:
                found._deactivate(temp = True)
            else:
                subject = self._fromXML(foundDef)
            return subject
        else:
            self.vreport(specUUID,"define new")
            return self._fromXML(specDef)

    def fromDefinitionFile(self,path):
        with open(path,"r") as f:
            specDef = f.read()
        return self.fromDefinition(specDef)
    
    def _hasDefinitionChanged(self,specDef,foundDef,subjectDef):
        return foundDef != subjectDef

class DomainConnection(ObjectConnection):
    def __init__(self,session):
        ObjectConnection.__init__(self,"domain",session)
    def _getAllLV(self):
        return self.conn.listAllDomains()
    def _lookupByUUID(self,objid):
        return self.conn.lookupByUUID(objid)
    def _lookupByName(self,name):
        return self.conn.lookupByName(name)
    def _defineXML(self,defn):
        return self.conn.defineXML(defn)
    def _descriptionXMLText(self,lvobj):
        # https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainXMLFlags
        # VIR_DOMAIN_XML_INACTIVE
        return lvobj.XMLDesc()
        #return lvobj.XMLDesc(flags=2)
    def _undefine(self,lvobj):
        # https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainUndefineFlagsValues
        # VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
        # VIR_DOMAIN_UNDEFINE_KEEP_NVRAM
        # VIR_DOMAIN_UNDEFINE_KEEP_TPM
        lvobj.undefineFlags(flags=73)
    def _hasDefinitionChanged(self,specDef,foundDef,subjectDef):
        # Check number of network interface between spec and found if they don't match def has changed 
        # for each interface in specdef
        #    match with interface in found and subject
        #    find mac in spec
        #    if none then check xmldiff between found and subject
        #        if only change is mac report no change FOR INTERFACE
        #        otherwise report change
        #    if mac found just compare as text FOPR INTERFACE
        # remove all interfaces from XML
        # compare rest as text

        specDefXML = lxml.etree.fromstring(specDef)
        foundDefXML = lxml.etree.fromstring(foundDef)
        subjectDefXML = lxml.etree.fromstring(subjectDef)

        # TODO deal with bridges
        specNetworkIntfs = specDefXML.xpath("/domain/devices/interface[@type='network']")
        foundNetworkIntfs = foundDefXML.xpath("/domain/devices/interface[@type='network']")
        subjectNetworkIntfs = subjectDefXML.xpath("/domain/devices/interface[@type='network']")

        if len(specNetworkIntfs) != len(foundNetworkIntfs):
            return True

        for i, specIntf in enumerate(specNetworkIntfs):
            foundIntf = foundNetworkIntfs[i]
            subjectIntf = subjectNetworkIntfs[i]

            specMac = specDefXML.xpath("/network/mac/@address")
            if not specMac:
                diff = xmldiff.diff_texts(lxml.etree.tostring(foundIntf), lxml.etree.tostring(subjectIntf))
                if len(diff) == 0: return False
                if len(diff) > 1:
                    return True
                diff = diff[0]
                if type(diff).__name__ == "UpdateAttrib" and diff.node == "/interface/mac[1]" and diff.name == "address":
                    continue
                return True
            elif lxml.etree.tostring(foundIntf) != lxml.etree.tostring(subjectIntf):
                return True
        
        for e in foundNetworkIntfs:
            e.getparent().remove(e)

        for e in subjectNetworkIntfs:
            e.getparent().remove(e)

        return lxml.etree.tostring(foundDefXML) != lxml.etree.tostring(subjectDefXML)

class NetworkConnection(ObjectConnection):
    def __init__(self,session):
        ObjectConnection.__init__(self,"network",session)
    def _getAllLV(self):
        return self.conn.listAllNetworks()
    def _lookupByUUID(self,objid):
        return self.conn.networkLookupByUUID(objid)
    def _lookupByName(self,name):
        return self.conn.networkLookupByName(name)
    def _defineXML(self,defn):
        # https://libvirt.org/formatnetwork.html
        return self.conn.networkDefineXML(defn)
    def _descriptionXMLText(self,lvobj):
        # https://libvirt.org/html/libvirt-libvirt-network.html#virNetworkXMLFlags
        # VIR_NETWORK_XML_INACTIVE
        return lvobj.XMLDesc(flags=1)
    def _getDependents(self,obj):
        names = [str(name) for name in obj.descriptionXMLETree().xpath("/network/bridge/@name")]
        domains = DomainConnection(self.session).getAll()
        deps = []
        for domain in domains:
            intfs = domain.descriptionXMLETree().xpath("/domain/devices/interface/source/@bridge")
            for intf in intfs:
                if str(intf) in names:
                    deps.append(domain)
                    break
        return deps
    def _addReconnectHooks(self, obj):
        net_name = str(obj.descriptionXMLETree().find("name").text)

        # TODO domains
        # can skip:
        # domains that will be deactive after activation
        # domains that will be deactivated as part of activation
        domains = DomainConnection(self.session).getAll()
        for domain in domains:
            # TODO deal with bridges
            intfs = domain.descriptionXMLETree().xpath("/domain/devices/interface[@type='network']")
            for intf in intfs:
                intf_net_name = (intf.xpath("./source/@network") or [""])[0]
                net_bridge = (intf.xpath("./source/@bridge") or [""])[0]
                net_target = (intf.xpath("./target/@dev") or [""])[0]
                if intf_net_name == net_name and net_bridge != "" and net_target != "":
                    self.session.addPostHook(["brctl", "addif", net_bridge, net_target])
    def _hasDefinitionChanged(self,specDef,foundDef,subjectDef):
        # find mac in spec
        #   if none then check xmldiff between found and subject
        #      if only change is mac report no change
        #      otherwise report change
        #   if mac found just compare as text
        specDefXML = lxml.etree.fromstring(specDef)

        specMac = specDefXML.xpath("/network/mac/@address")

        if not specMac:
            diff = xmldiff.diff_texts(foundDef, subjectDef)
            if len(diff) == 0: return False
            if len(diff) > 1: return True
            diff = diff[0]
            if type(diff).__name__ == "UpdateAttrib" and diff.node == "/network/mac[1]" and diff.name == "address":
                return False
            return True
        else:
            return foundDef != subjectDef

# https://libvirt.org/html/libvirt-libvirt-storage.html
class PoolConnection(ObjectConnection):
    def __init__(self,session):
        ObjectConnection.__init__(self,"pool",session)
    def _getAllLV(self):
        return self.conn.listAllStoragePools()
    def _lookupByUUID(self,objid):
        return self.conn.storagePoolLookupByUUID(objid)
    def _lookupByName(self,name):
        return self.conn.storagePoolLookupByName(name)
    def _defineXML(self,defn):
        # https://libvirt.org/formatstorage.html
        return self.conn.storagePoolDefineXML(defn)
    def _descriptionXMLText(self,lvobj):
        # https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageXMLFlags
        # VIR_STORAGE_XML_INACTIVE
        return lvobj.XMLDesc(flags=1)

objectTypes = ['domain','network','pool']

def getObjectConnection(session,type):
    match type:
        case "domain":
            return DomainConnection(session)
        case "network":
            return NetworkConnection(session)
        case "pool":
            return PoolConnection(session)

class VObject:
    def __init__(self,oc,lvobj):
        self.oc = oc
        self._lvobj = lvobj
        self.uuid = lvobj.UUID()

    def vreport(self,msg):
        self.oc.vreport(self.uuid,msg)

    def isActive(self):
        return self._lvobj.isActive()

    def _activate(self):
        if not self.isActive():
            self.vreport("activate")
            self._lvobj.create()

    def _deactivate(self,temp = False):
        if self.isActive():
            if temp:
                self.oc._recordTempDeactivated(self.uuid)
                self.oc._addReconnectHooks(self)
            self.vreport("deactivate (temporary)" if temp else "deactivate")
            self._lvobj.destroy()

    def setActive(self,s):
        match s:
            case True:
                self._activate()
            case False:
                self._deactivate()
            case null:
                # reactivate objects that were temporatily deactivated
                if self.oc._wasTempDeactivated(self.uuid):
                    self._activate()

    def setAutostart(self,a):
        self.vreport("set autostart true" if a else "set autostart false")
        self._lvobj.setAutostart(a)

    def descriptionXMLText(self):
        return self.oc._descriptionXMLText(self._lvobj)

    def descriptionXMLETree(self):
        return lxml.etree.fromstring(self.descriptionXMLText())

    def undefine(self):
        isPersistent = self._lvobj.isPersistent()
        self._deactivate()
        if isPersistent:
            self.vreport("undefine")
            self.oc._undefine(self._lvobj)
