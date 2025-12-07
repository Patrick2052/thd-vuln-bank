import os

SECURE_MODE = os.environ.get("SECURE", False)
if SECURE_MODE is False or SECURE_MODE.lower() == "false":
    SECURE_MODE = False
elif SECURE_MODE.lower() == "true" and SECURE_MODE is not False:
    SECURE_MODE = True


print(f"\n\n {'*'*15}\n")
print(f"SECURE MODE: {SECURE_MODE}")
print(f"\n {'*'*15}")



UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
