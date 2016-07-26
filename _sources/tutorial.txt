Tutorial
========

An analyst will first initialize a device and call `get_sensors()` to see
the available sensors on the device.

.. code-block:: python
  :linenos:

  >>> import ocd
  >>> device = ocd.Device('localhost')
  >>> sensors = device.get_sensors()
  >>> print sensors
  [<NetworkSensor backend='pyshark'>,
   <AuthSensor backend='sys'>,
   <FileSensor backend='sys'>]

To use a sensor, analyst may first check the available features.

.. code-block:: python
  :linenos:

  >>> sensor = sensors[0]
  >>> sensor.get_features()
  ['load', 'stat_macs', 'sniff', 'stat_ports', 'unique_ports',
   'stat_protocols', 'get_supported_backends', 'unique_ips',
   'unique_protocols', 'unique_macs', '__repr__', '__init__',
   'get_installed_backends', 'get_features', 'stat_ips']

To further look up the specification, analyst may pass in the feature name
as argument.

.. code-block:: python
  :linenos:

  >>> print sensor.get_features('stat_ips')
  Get a dict of ips and their freq

  It can be either src ip or dst ip. If src ip is specified,
  then dst ips are returned, vice versa. If none is specified,
  all unique ips will be returned.

  Args:
      time_slot (optional[tuple(datetime)]): a tuple of two
          specifying the start and end time as datetime

      src_ip (optional[list(str), or single str]): src ip(s).

      dst_ip (optional[list(str), or single str]): dst ip(s),
          src_ip and dst_ip should not be both specified.

  Returns:
      dict{str->int}: ip addresses and freq.

To call this `stat_ips()`, analyst may first sniff for a while, and then see
the result.

.. code-block:: python
  :linenos:

  >>> sensor.sniff(interface='en0', timeout=10)
  >>> sensor.stat_ips()
  {'104.107.25.25': 32,
   '104.20.14.64': 48,
   '128.2.220.105': 13,
   '128.237.160.2': 4,
   ...
   '8.8.8.8': 52}

Other sensors are similar. See `API reference <api.html>`_ for detail.
