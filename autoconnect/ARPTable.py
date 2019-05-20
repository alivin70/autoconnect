class ARPTableEntry:
    def __init__(self, ipaddress, macaddress):
        self.ipaddress = ipaddress
        self.macaddress = macaddress
        self.count = 0


class ARPTable:
    def __init__(self):
        self.table = {}

    def addOrUpdateEntry(self, ipaddress, macaddress):
        entry = self.table.get(ipaddress)
        if entry is None:
            self.table[ipaddress] = ARPTableEntry(ipaddress, macaddress)
        else:
            if macaddress != '00:00:00:00:00:00' and entry.macaddress != '00:00:00:00:00:00':
                entry.macaddress = macaddress
            entry.count += 1

    def contains(self, ipaddress):
        return ipaddress in self.table