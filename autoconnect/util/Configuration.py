import xml.etree.ElementTree as ET


class Configuration:
    def __init__(self):
        self.interface = None

    def parse_configurations(self, conf_file):
        tree = ET.parse(conf_file)
        root = tree.getroot()
        for child in root:
            if child.tag == 'interface':
                self.interface = child.text.strip()