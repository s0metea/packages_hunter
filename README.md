# Packages Hunter                                                                                        
                                                                                        
                                                                                            
    #####   #   #   # #   #   #   ##### #####  ####     #   # #   # #   # ##### ##### ####  
    #   #  # #  #   # #  #   # #  #   # #     #          # #   # #  #   #   #   #     #   # 
    #   # #####  #### ###   ##### #     ####  #           #     #   #####   #   ####  ####  
    #   # #   #     # #  #  #   # #     #     #          # #   #    #   #   #   #     #     
    #   # #   #     # #   # #   # #     #####  ####     #   # #     #   #   #   ##### #                                            

Explore npm packages to find maintainers with expired domains.
The idea was inspired by the post located here: https://thehackerblog.com/zero-days-without-incident-compromising-angular-via-expired-npm-publisher-email-domains-7kZplW4x/

## Usage
- Recursively explore single package.json:
  `python3 main.py -f packages.json --depth 100`
- Recursively explore single npm package:
  `python3 main.py -p vue:2.6.11 --depth 100`
- Explore all package.json files located in your bitbucket repo (Don't forget to add bitbucket_token in main.py):
  `python3 main.py -fb --depth 100`
