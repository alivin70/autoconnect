class ARPTableEntry:
    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.count = 1


class ARPTable:
    def __init__(self):
        self.table = {}

    def add_or_update_entry(self, ip_address, mac_address):
        entry = self.table.get(ip_address)
        if entry is None:
            self.table[ip_address] = ARPTableEntry(ip_address, mac_address)
        else:
            if mac_address != '00:00:00:00:00:00' and entry.mac_address == '00:00:00:00:00:00':
                entry.mac_address = mac_address
            entry.count += 1

    def print(self):
        for entry in self.table:
            print(self.table[entry].ip_address + "\t" + self.table[entry].mac_address + "\t" +
                  str(self.table[entry].count))

    def contains(self, ip_address):
        return ip_address in self.table
