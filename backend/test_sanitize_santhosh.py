from app import remove_text

s = "My name is santhosh and here santhosh is to be redacted. Also Santhosh's account failed."
redacted, removed = remove_text(s)
print('REDACTED:\n' + redacted)
print('\nREMOVED_ITEMS:')
print(removed)
