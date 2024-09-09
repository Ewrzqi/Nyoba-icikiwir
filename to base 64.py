import base64

text = input("input text : ") 

text_bytes = text.encode('utf-8')
encoded = base64.b64encode(text_bytes)
encoded_str = encoded.decode('utf-8')

print(encoded_str)

