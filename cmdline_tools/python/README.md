# IDEAS:

* ~~template creating tool (already done actually, need to push it from macbook)~~
  * mb make whole sploit more OOP-like
  * quick patches against issues with debug in remote mode (kind of annoying)
  * add /proc/ parsing to get adress base
  ```python
     def get_base_address(proc):
        return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)
  ```
