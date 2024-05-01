import sys, uuid, hashlib, lxml, xmldiff.main, xmldiff.formatting, libvirt, copy

# Switch off annoying libvirt stderr messages
# https://stackoverflow.com/a/45543887
def libvirt_callback(userdata, err):
    pass
libvirt.registerErrorHandler(f=libvirt_callback, ctx=None)

class Session:
    def __init__(self,uri,verbose):
        self.conn = libvirt.open(uri)
        self.verbose = verbose

    def vreport(self,msg):
        if self.verbose:
            print (msg, file=sys.stderr)

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
    
    def fromNameOrNone(self,name):
        try:
            return self.fromName(name)
        except libvirt.libvirtError:
            return None

    def _fromXML(self,defn):
        return self._fromLVObject(self._defineXML(defn))

    def _undefine(self,lvobj):
        lvobj.undefine()

    def _getDependents(self,obj):
        return []

    def _deactivateDependents(self,obj):
        return
        dependents = self._getDependents(obj)
        for dependent in dependents:
            dependent._deactivate()

    def _fixDefinitionXML(self,subject, specDefXML):
        return None

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
    def _descriptionXMLText(self,lvobj, active = False):
        # https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainXMLFlags
        # VIR_DOMAIN_XML_INACTIVE
        if active:
            return lvobj.XMLDesc()
        else:
            return lvobj.XMLDesc(flags=2)
    def _undefine(self,lvobj):
        # https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainUndefineFlagsValues
        # VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
        # VIR_DOMAIN_UNDEFINE_KEEP_NVRAM
        # VIR_DOMAIN_UNDEFINE_KEEP_TPM
        lvobj.undefineFlags(flags=73)
    def _fixDefinitionXML(self,subject,specDefXML):
        if subject is None: return specDefXML
        resultXML = copy.deepcopy(specDefXML)
        subjectXML = subject.descriptionXMLETree()

        # fill UID
        specUUID = specDefXML.xpath("/domain/uuid")
        subjectUUID = subjectXML.xpath("/domain/uuid")
        if len(subjectUUID) == 1 and  len(specUUID) == 0:
            uuid = lxml.etree.Element("uuid")
            uuid.text = subjectUUID[0].text
            resultXML.append(uuid)
            
        # Fill Macs in interfaces
        specInterfaces = resultXML.xpath("/domain/devices/interface")
        subjectInterfaces = subjectXML.xpath("/domain/devices/interface")

        # If the number of interfaces are different we will need to reset anyway
        # don't try to till in macs
        if len(specInterfaces) != len(subjectInterfaces): return resultXML

        newMacs = []
        for index, specInterface in enumerate(specInterfaces):
            subjectInterface = subjectInterfaces[index]

            subjectType = subjectInterface.attrib["type"]
            specType = subjectInterface.attrib["type"]

            specMac = specInterface.xpath("/interface/mac/@address")
            subjectMac = subjectInterface.xpath("/interface/mac/@address")

            if subjectType != specType: return resultXML
            if specMac != subjectMac and len(specMac) > 0: return resultXML

            if len(specMac) == 0 and len(subjectMac) == 1:
                mac = lxml.etree.Element("mac")
                mac.attrib["address"] = subjectMac[0]
                newMacs.append(mac)
            else:
                newMacs.append(None)
        
        for index, mac in enumerate(newMacs):
            if mac is not None:
                specInterfaces[index].append(mac)

        return resultXML

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
    def _descriptionXMLText(self,lvobj, active = False):
        # https://libvirt.org/html/libvirt-libvirt-network.html#virNetworkXMLFlags
        # VIR_NETWORK_XML_INACTIVE
        if active:
            return lvobj.XMLDesc()
        else:
            return lvobj.XMLDesc(flags=1)
    def _getDependents(self,obj):
        networknames = [name.text for name in obj.descriptionXMLETree().xpath("/network/name")]
        bridgenames = [str(name) for name in obj.descriptionXMLETree().xpath("/network/bridge/@name")]
        domains = DomainConnection(self.session).getAll()
        deps = []
        for domain in domains:
            domainbridgenames = domain.descriptionXMLETree().xpath("/domain/devices/interface[@type='bridge']/source/@bridge")
            for name in domainbridgenames:
                if str(name) in bridgenames:
                    deps.append(domain)
                    break
            domainnetworknames = domain.descriptionXMLETree().xpath("/domain/devices/interface[@type='network']/source/@network")
            for name in domainnetworknames:
                if str(name) in networknames:
                    deps.append(domain)
                    break
        return deps
    def _fixDefinitionXML(self,subject,specDefXML):
        if subject is None: return specDefXML
        resultXML = copy.deepcopy(specDefXML)
        subjectXML = subject.descriptionXMLETree()

        # fill UID
        specUUID = specDefXML.xpath("/network/uuid")
        subjectUUID = subjectXML.xpath("/network/uuid")
        if len(subjectUUID) == 1 and  len(specUUID) == 0:
            uuid = lxml.etree.Element("uuid")
            uuid.text = subjectUUID[0].text
            resultXML.append(uuid)
        
        specMac = resultXML.xpath("/network/mac/@address")
        subjectMac = subjectXML.xpath("/network/mac/@address")

        if len(specMac) == 0 and len(subjectMac) == 1:
            mac = lxml.etree.Element("mac")
            mac.attrib["address"] = subjectMac[0]
            resultXML.append(mac)
        
        return resultXML

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

    def _deactivate(self):
        if self.isActive():
            self.oc._deactivateDependents(self)
            self.vreport("deactivate")
            self._lvobj.destroy()

    def setActive(self,s):
        if s:
            self._activate()
        else:
            self._deactivate()

    def setAutostart(self,a):
        self.vreport("set autostart true" if a else "set autostart false")
        self._lvobj.setAutostart(a)

    def descriptionXMLText(self, active = False):
        return self.oc._descriptionXMLText(self._lvobj, active)

    def descriptionXMLETree(self, active = False):
        return lxml.etree.fromstring(self.descriptionXMLText(active))

    def undefine(self):
        isPersistent = self._lvobj.isPersistent()
        self._deactivate()
        if isPersistent:
            self.vreport("undefine")
            self.oc._undefine(self._lvobj)

# what we want for an object
class ObjectSpec:

    def __init__(self,oc,specDef,active = None):
        specDefXML = lxml.etree.fromstring(specDef)

        # Domain def must contain name, UUID is optional
        self.specName = specDefXML.find("name").text

        specUUIDElem = specDefXML.find("uuid")
        if specUUIDElem is not None:
            self.specUUID = uuid.UUID(specUUIDElem.text).bytes
            self.subject = oc.fromUUIDOrNone(self.specUUID)
        else:
            self.subject = oc.fromNameOrNone(self.specName)
            self.specUUID = None
            if self.subject:
                self.specUUID = self.subject.uuid
        
        self.specDefXML = oc._fixDefinitionXML(self.subject, specDefXML)
        self.specDef = lxml.etree.tostring(self.specDefXML).decode("utf-8")
        self.oc = oc
        self.active = active

    def vreport(self,msg):
        self.oc.vreport(self.specUUID,msg)

    def fromDefinition(oc,specDef,active):
        return ObjectSpec(oc,specDef,active = active)

    def fromDefinitionFile(oc,path,active):
        with open(path,"r") as f:
            specDef = f.read()
        return ObjectSpec.fromDefinition(oc,specDef,active)

    def define(self):
        if self.specDefXML is not None:
            if self.subject is not None:
                foundDef = self.subject.descriptionXMLText()
                foundDefXML = lxml.etree.fromstring(foundDef)
                foundName = foundDefXML.find("name").text
                if foundName != self.specName:
                    self.subject.undefine()
                self.vreport("redefine")
                newvobject = self.oc._fromXML(self.specDef)
                subjectDef = newvobject.descriptionXMLText()
                if foundDef != subjectDef:
                    diff = xmldiff.main.diff_texts(foundDef,subjectDef,formatter = xmldiff.formatting.DiffFormatter())
                    self.vreport("changed:\n" + diff)
                    self.subject._deactivate()
                    self.subject = newvobject
                    return "changed"
                else:
                    self.vreport("unchanged")
                    self.subject = newvobject
                    return "unchanged"
            else:
                self.vreport("define new")
                self.subject = self.oc._fromXML(self.specDef)
                return "new"

    def setActive(self):
        self.subject.setActive(self.active)
