import scrapy
import re
import sys
from colorama import Fore, Style

class SecretsSpider(scrapy.Spider):
    name = 'secrets_spider'
    start_urls = []
    regex = {
        "Secret_Amazon_AWS_Access_Key_ID": "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
        "Secret_Amazon_AWS_S3_Bucket_1": "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
        "Secret_Amazon_AWS_S3_Bucket_2": "//s3\\.amazonaws\\.com/[a-z0-9._-]+",
        "Secret_Amazon_AWS_S3_Bucket_3": "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
        "Secret_Amazon_AWS_S3_Bucket_4": "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
        "Secret_Amazon_AWS_S3_Bucket_5": "[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
        "Secret_Amazon_AWS_S3_Bucket_6": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        # "Secret_Artifactory_API_Token": "(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
        # "Secret_Artifactory_Password": "(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}",
        # "Secret_Authorization_Basic": "basic\\s[a-zA-Z0-9_\\-:\\.=]+",
        "Secret_Authorization_Bearer": "bearer\\s[a-zA-Z0-9_\\-:\\.=]+",
        "Secret_AWS_API_Key": "AKIA[0-9A-Z]{16}",
        # "Secret_Basic_Auth_Credentials": "(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+",
        "Secret_Cloudinary_Basic_Auth": "cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
        # "Secret_DEFCON_CTF_Flag": "O{3}\\{.*\\}",
        # "Secret_Discord_BOT_Token": "((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$",
        # "Secret_Facebook_Access_Token": "EAACEdEose0cBA[0-9A-Za-z]+",
        # "Secret_Facebook_ClientID": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K](.{0,20})?['\"][0-9]{13,17}",
        # "Secret_Facebook_OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
        # "Secret_Facebook_Secret_Key": "([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?['\"][0-9a-f]{32}",
        "Secret_Firebase": "[a-z0-9.-]+\\.firebaseio\\.com",
        # "Secret_Generic_API_Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
        # "Secret_Generic_Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
        # "Secret_GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
        # "Secret_GitHub_Access_Token": "([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$",
        # "Secret_Google_API_Key": "AIza[0-9A-Za-z\\-_]{35}",
        # "Secret_Google_Cloud_Platform_OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
        # "Secret_Google_Cloud_Platform_Service_Account": "\"type\": \"service_account\"",
        # "Secret_Google_OAuth_Access_Token": "ya29\\.[0-9A-Za-z\\-_]+",
        # "Secret_HackerOne_CTF_Flag": "[h|H]1(?:[c|C][t|T][f|F])?\\{.*\\}",
        # "Secret_HackTheBox_CTF_Flag": "[h|H](?:[a|A][c|C][k|K][t|T][h|H][e|E][b|B][o|O][x|X]|[t|T][b|B])\\{.*\\}$",
        # "Secret_Heroku_API_Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        # "Secret_IP_Address": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
        # "Secret_JSON_Web_Token": "(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\\.){2}(?:[a-z0-9_\\-\\+\/=]*))$",
        # "Secret_LinkFinder": "(?:\"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^\"'\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:\/|\\.\\.\/|\\.\/)[^\"'><,;| *()(%%$^\/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|)))(?:\"|')",
        # "Secret_Mac_Address": "(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$",
        # "Secret_MailChimp_API_Key": "[0-9a-f]{32}-us[0-9]{1,2}",
        # "Secret_Mailgun_API_Key": "key-[0-9a-zA-Z]{32}",
        # "Secret_Mailto": "(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+",
        # "Secret_Password_in_URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
        # "Secret_PayPal_Braintree_Access_Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
        # "Secret_PGP_private_key_block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        # "Secret_Picatic_API_Key": "sk_live_[0-9a-z]{32}",
        # "Secret_RSA_Private_Key": "-----BEGIN RSA PRIVATE KEY-----",
        # "Secret_Slack_Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        # "Secret_Slack_Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        # "Secret_Square_Access_Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
        # "Secret_Square_OAuth_Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
        # "Secret_SSH_DSA_Private_Key": "-----BEGIN DSA PRIVATE KEY-----",
        # "Secret_SSH_EC_Private_Key": "-----BEGIN EC PRIVATE KEY-----",
        # "Secret_Stripe_API_Key": "sk_live_[0-9a-zA-Z]{24}",
        # "Secret_Stripe_Restricted_API_Key": "rk_live_[0-9a-zA-Z]{24}",
        # "Secret_TryHackMe_CTF_Flag": "[t|T](?:[r|R][y|Y][h|H][a|A][c|C][k|K][m|M][e|E]|[h|H][m|M])\\{.*\\}$",
        # "Secret_Twilio_API_Key": "SK[0-9a-fA-F]{32}",
        # "Secret_Twitter_Access_Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
        # "Secret_Twitter_ClientID": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?['\"][0-9a-z]{18,25}",
        # "Secret_Twitter_OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
        # "Secret_Twitter_Secret_Key": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?['\"][0-9a-z]{35,44}"
    }

    def __init__(self, *args, **kwargs):
        super(SecretsSpider, self).__init__(*args, **kwargs)
        self.js_files_path = [kwargs.get('js_files_path')]

        with open(f"{self.js_files_path[0]}", 'r') as js_files:
            for js_file in js_files:
                self.start_urls.append(js_file.strip())

        self.results = []
        self.log_level = 'CRTICAL'  # Set logging level to ERROR to suppress most logs
        self.log_enabled = False

    def parse(self, response):
        # Extract text content from the JavaScript file
        js_content = response.text

        # Define patterns for cloud-related secrets
        for key, value in self.regex.items():
            globals()[key] = re.compile(rf'{value}')

        # Search for patterns in the combined content
        for key, value in self.regex.items():
            globals()[key] = (globals()[key]).findall(js_content)

        # Format the results
        for name, value in globals().items():
            if name.startswith('Secret_') and not callable(value):
                if value:
                    self.results.append({name: value})

    def closed(self, reason):
        # Re-enable stdout
        sys.stdout = sys.__stdout__

        # Print the collected results
        if self.results:
            print(f'{Fore.GREEN}    [+] Cloud related secrets founded:{Style.RESET_ALL}')
            for result in self.results:
                for key, value in result.items():
                    print(f'        => {key}:')
                    for item in value:
                        print(f'          - {item}')
