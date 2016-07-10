# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""

from sensor import Sensor


class Device(object):
    def __init__(self, addr='localhost'):
        """ Init a device at addr

        Args:
            addr: address of device. Currently only 'localhost'
                  is supported.
        """
        pass

    def get_sensors(self):
        """ Get a list of available sensors on this device.

        Returns:
            list[Sensor]
        """
        sensors = []
        clss = Sensor.__subclasses__()
        for cls in clss:
            backends = cls.get_installed_backends()
            for backend in backends.keys():
                try:
                    sensors.append(cls(backend))
                except NotImplementedError:
                    pass
        return sensors
