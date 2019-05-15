from abc import ABC, abstractmethod


class ConnectionAttempt (ABC):

    def __init__(self):
        pass

    @abstractmethod
    def connect(self):
        pass