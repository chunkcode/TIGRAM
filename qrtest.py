import base64
import qrcode
import io
def get_qr_string():
 qr = qrcode.QRCode(border=4)
 qrcode_string = "hello"
 qr.add_data(qrcode_string)
 qr.make(fit=True)
 img = qr.make_image()
 buffered = io.BytesIO()
 img.save(buffered, format="PNG")
 img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
 return img_str
# img.save("./img.png")