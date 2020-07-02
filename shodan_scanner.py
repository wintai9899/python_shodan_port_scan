import shodan

import pprint

class Shodan_Finder():

    def search_for_ports(self,API_KEY,target):
        global results
        results = {}
        module_list = []
        product_list = []
        domain_list = []
        asn_list = []
        hostname_list = []
        version_list = []
        transport_list = []
        isp_list = []
        data_list = []
        location_list = []
        try:
            api = shodan.Shodan(API_KEY)
            host = api.host(target)
            port_list = []
            ports = {}

            '-------------------PORT SCANNER--------------------'
            for port in host['ports']:
                port_list.append(port)
            #print(port_list)

            for item in host['data']:

                '获取端口信息'
                shodan_data = (item['_shodan'])
                module_list.append(shodan_data.get('module',''))

                product_data = item.get('product','')
                product_list.append(product_data)

                data = item.get('data','')
                data_list.append(data)

                version = item.get('version', '')
                version_list.append(version)

                'IP信息'
                transport = item['transport']
                transport_list.append(transport)

                ip = item.get('ip_string','')

                domain = item['domains']
                domain_list.append(domain)

                hostname = item['hostnames']
                hostname_list.append(hostname)

                isp = item['isp']
                isp_list.append(isp)

                asn = item['asn']
                asn_list.append(asn)

            '整合成一个字典'
            print(module_list)

            for m,pd,v,t in zip(module_list,product_list,version_list,transport_list):
                ports_info = {'service':m, 'product':pd,'version':v,'protocol':t,}
                ports = dict.fromkeys(port_list, ports_info)


            results['ports'] = ports
            #pprint.pprint(results)
        except Exception as e:

            print('Error:{}'.format(e))



if __name__ == ('__main__'):
    result = Shodan_Finder()
    result.search_for_ports('YOUR_API_KEY', '121.14.49.216')