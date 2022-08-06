# aiox_monitor_and_reconnect
This is a quick hack to get the buggy router a-wr307n to connect as a client on a wifi network and bridge with its
ethernet ports.
Also this script will monitor for wifi connectivity and when disconnected it tries to restablish the connection and
restarts the router.
The motivation comes from the fact that some access points periodically changes channel over time and this
older model router gets kicked out from wifi when this happens. By scanning the access points and retrieving correct 
channel info the connection can be reestablished in an automatic fashion.

The windows executable can be created by running command "python setup.py py2exe".
Parameters are stored in config.json file and that must be in the same directory as the executable.
