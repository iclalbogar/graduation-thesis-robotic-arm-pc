import usb.core
import usb.util
import logging
import time


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MCXN947_USB_Comm:
    
    def __init__(self, vid, pid, timeout=1000):
        self.vid = vid
        self.pid = pid
        self.timeout = timeout
        
        self.device = None
        self.endpoint_in = None
        self.endpoint_out = None
        self.interface_num = 0

    def connect(self):
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)

        if self.device is None:
            logging.error(f"Device cannot found! VID: {hex(self.vid)}, PID: {hex(self.pid)}")
            return False

        logging.info("Device found. Configuring...")

        if self.device.is_kernel_driver_active(self.interface_num):
            try:
                self.device.detach_kernel_driver(self.interface_num)
                
            except usb.core.USBError as e:
                return False

        try:
            self.device.set_configuration()
            
            cfg = self.device.get_active_configuration()
            intf = cfg[(self.interface_num, 0)]

            self.endpoint_out = usb.util.find_descriptor(
                intf,
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            )

            self.endpoint_in = usb.util.find_descriptor(
                intf,
                custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            )

            if self.endpoint_out is None or self.endpoint_in is None:
    
                return False

            logging.info(f"OUT Endpoint: {hex(self.endpoint_out.bEndpointAddress)}")
            logging.info(f"IN Endpoint: {hex(self.endpoint_in.bEndpointAddress)}")
            return True

        except usb.core.USBError as e:
            return False

    def write(self, data):
        if self.device is None or self.endpoint_out is None:
            return 0

        try:
            bytes_written = self.device.write(self.endpoint_out.bEndpointAddress, data, self.timeout)
          
            return bytes_written
        except usb.core.USBError as e:
    
            return 0

    def read(self, size=64):
       
        if self.device is None or self.endpoint_in is None:
         
            return None

        try:
            data = self.device.read(self.endpoint_in.bEndpointAddress, size, self.timeout)
          
            return data
        except usb.core.USBError as e:
            if e.errno == 110 or 'timeout' in str(e).lower():
                logging.debug("Timeout.")
            else:
                logging.error(f"Data read error: {str(e)}")
            return None

    def disconnect(self):
        if self.device is not None:
            try:
                usb.util.dispose_resources(self.device)
            except Exception as e:
                logging.error(f"Disconnection error: {str(e)}")
            finally:
                self.device = None
                self.endpoint_in = None
                self.endpoint_out = None

if __name__ == "__main__":
    TARGET_VID = 0x1FC9  
    TARGET_PID = 0x0090 
    
    mcx = MCXN947_USB_Comm(vid=TARGET_VID, pid=TARGET_PID, timeout=2000)
    
    if mcx.connect():
        try:
            test_data = [0x01, 0x02, 0x03, 0x04]
            logging.info(f"Data sending: {test_data}")
            mcx.write(test_data)
            
            time.sleep(0.1) 
            
            logging.info("Respons is waiting")
            response = mcx.read(size=64)
            if response:
                logging.info(f"Receive data (Raw): {response}")
                logging.info(f"Receive data (Hex): {[hex(x) for x in response]}")
                
        except KeyboardInterrupt:
            logging.info("Interrupted by user.")
        finally:
            mcx.disconnect()
    else:
        logging.error("Connection canceled.")