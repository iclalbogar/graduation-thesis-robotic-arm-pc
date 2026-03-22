import os
import usb.core
import usb.backend.libusb1
import usb.util
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

current_dir = os.path.dirname(os.path.abspath(__file__))
dll_path = os.path.join(current_dir, "libusb-1.0.dll")

logging.info(f"Loading libusb backend from: {dll_path}")
libusb_backend = usb.backend.libusb1.get_backend(find_library=lambda x: dll_path)

if libusb_backend is None:
    logging.error("CRITICAL: Failed to load libusb backend. Make sure libusb-1.0.dll is in the same folder as this script.")
    exit(1)

def list_usb_devices():
    logging.info("Scanning for connected USB devices...")
    devices = usb.core.find(find_all=True, backend=libusb_backend)
    
    found_devices = False
    for dev in devices:
        found_devices = True
        try:
            manufacturer = usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else "Unknown"
            product = usb.util.get_string(dev, dev.iProduct) if dev.iProduct else "Unknown"
            logging.info(f"Device Found -> VID: {hex(dev.idVendor):<6} | PID: {hex(dev.idProduct):<6} | {manufacturer} - {product}")
        except Exception:
            logging.info(f"Device Found -> VID: {hex(dev.idVendor):<6} | PID: {hex(dev.idProduct):<6} | (Names blocked by OS)")
            
    if not found_devices:
        logging.warning("No USB devices found.")
    print("-" * 50)

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
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=libusb_backend)

        if self.device is None:
            logging.error(f"Device cannot be found! VID: {hex(self.vid)}, PID: {hex(self.pid)}")
            return False

        logging.info("Device found. Configuring...")

        try:
            if self.device.is_kernel_driver_active(self.interface_num):
                self.device.detach_kernel_driver(self.interface_num)
        except NotImplementedError:
            pass 
        except usb.core.USBError as e:
            logging.warning(f"Failed to detach kernel driver: {e}")

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
                logging.error("Could not find OUT or IN endpoints.")
                return False

            logging.info(f"OUT Endpoint: {hex(self.endpoint_out.bEndpointAddress)}")
            logging.info(f"IN Endpoint: {hex(self.endpoint_in.bEndpointAddress)}")
            return True

        except usb.core.USBError as e:
            logging.error(f"Configuration error: {e}")
            return False

    def write(self, data):
        if self.device is None or self.endpoint_out is None:
            return 0
        try:
            return self.device.write(self.endpoint_out.bEndpointAddress, data, self.timeout)
        except usb.core.USBError as e:
            logging.error(f"Data write error: {e}")
            return 0

    def read(self, size=64):
        if self.device is None or self.endpoint_in is None:
            return None
        try:
            return self.device.read(self.endpoint_in.bEndpointAddress, size, self.timeout)
        except usb.core.USBError as e:
            if e.errno == 110 or 'timeout' in str(e).lower():
                logging.debug("Timeout waiting for data.")
            else:
                logging.error(f"Data read error: {str(e)}")
            return None

    def write_string(self, text, append_newline=True):
        if append_newline and not text.endswith('\n'):
            text += '\n'
            
        byte_data = text.encode('utf-8')
        return self.write(byte_data)

    def read_string(self, size=64):
        raw_data = self.read(size)
        
        if raw_data:
            try:
                return bytes(raw_data).decode('utf-8').rstrip('\x00\r\n')
            except UnicodeDecodeError:
                logging.warning(f"Received bytes, but they aren't valid UTF-8 text. Raw: {raw_data}")
                return None
        return None

    def disconnect(self):

        if self.device is not None:
            try:
                usb.util.dispose_resources(self.device)
                logging.info("Device disconnected.")
            except Exception as e:
                logging.error(f"Disconnection error: {str(e)}")
            finally:
                self.device = None
                self.endpoint_in = None
                self.endpoint_out = None

if __name__ == "__main__":
    
    TARGET_VID = 0x1fc9
    TARGET_PID = 0x143
    
    mcx = MCXN947_USB_Comm(vid=TARGET_VID, pid=TARGET_PID, timeout=2000)
    
    if mcx.connect():
        try:
            command = "Merhaba Dunya"
            logging.info(f"Sending String: '{command}'")
            
            mcx.write_string(command)
            
            time.sleep(0.1) 
        
            logging.info("Waiting for string response from board...")
            response_str = mcx.read_string(size=64)

            if response_str:
                logging.info(f"Board Replied: '{response_str}'")
            else:
                logging.info("No text response received from board.")
                
        except KeyboardInterrupt:
            logging.info("Interrupted by user.")
        finally:
            mcx.disconnect()
    else:
        logging.error("Connection canceled.")