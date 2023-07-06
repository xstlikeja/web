#Python3
#python3 portscan.py -h <要扫描的ip> -p <起始ip>-<结束ip>

from socket import * #网络编程的基础库，提供套接字功能
import threading #多线程库，用于同时运行多个程序
import re #正则库，用于字符串模式匹配
import sys #提供python与环境交互的功能，用于接收命令行参 数
import getopt #用于解析命令行参数，便于解析命令行传入的参数

def portScanner_1(host , port , openports):
    try:
        s = socket(AF_INET , SOCK_STREAM) #创建一个基于网络并使用tcp协议的套接字，用于通信，udp是sock_dgram
        s.connect((host , port)) #调用套接字方法，连接目标主机和端口，失败抛出异常
        #print('[+] %d open' %port)
        openports.append(port) #追加连接成功的端口
        s.close() #关闭套接字连接
    except:
        pass #如果连接不上就跳过

def portScanner_2(ip , portlist , openports = []):
    nloops = range(len(portlist)) #生成0-(len(portlist)-1)的列表
    threads= []
    for i in nloops: #执行len(portlist)
        t = threading.Thread(target = portScanner_1 , args = (ip , portlist[i] , openports))
        #target参数用来输入你要执行的的函数。注意不是调用，所以函数后面不加括号,args作为target的参数列表
        threads.append(t) #将线程对象添加进去threads列表中
    for i in nloops:
        threads[i].start() #逐个启动线程
    for i in nloops:
        threads[i].join() #逐个等待线程执行完成

def main():
    banner = r'''
    _____           _      _____                 
    |  __ \         | |    / ____|                
    | |__) |__  _ __| |_  | (___   ___ __ _ _ __  
    |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \ 
    | |  | (_) | |  | |_   ____) | (_| (_| | | | |
    |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|
    '''
    print(banner) #使用banner在线工具，用于生成如下花体字
    setdefaulttimeout(1) #经过1秒后还未成功，自动进入下一步操作，此次操作失败
    openports = [] #用于存放扫描到的开放的端口
    portlist = [] #要扫描的端口列表
    if len(sys.argv) == 1: #没有输入参数
        print("    python3 portscan.py -h <ip> -p <start ip>-<end ip>")
        exit() #退出python程序
    try:
        option , arg = getopt.getopt(sys.argv[1:] , 'h:p:') #argv参数列表，第二个开始为用户输入的参数，argc是参数个数
        #getopt返回两个列表:opts为解析出的格式信息，atgs为不属于格式信息的剩余信息，h:p:意思是h和p都需要一个参数
        openport = []
        for opt , val in option: #遍历形如[('-h' , '127.0.0.1') , ('-p' , '0-1024')]的参数列表
            if opt in ('-h'): #获取ip
                host = val #host保存要扫描的主机
            elif opt in ('-p'): #获取端口范围
                ports = val.split('-') #split以-拆分成数组
                start_port = ports[0] #这里保存起始端口
                end_port = ports[1] #这里保存结束端口

        for p in range(int(start_port) , int(end_port)):
            portlist.append(p) #按照用户输入的参数，生成待扫描的ip列表
        
        portScanner_2(host , portlist , openports) #传入带扫描的主机，需要扫描的端口列表，开放的端口列表
        #print(input_ip)
        print("        IP:" + host) #打印扫描的主机
        print("Open Ports:" + str(openports)) #输出开放的端口
    except ValueError as e:
        print("INPUT ERROR!!!") #命令行接收参数失败

if __name__ == '__main__':
    main()

'''
portScanner_1该函数的参数由目标主机ip，要扫描的端口号，开放的端口列表组成，
该函数通过错误处理的方式来判断所进行的连接是否成功，如果成功就将该端口添加至
开放端口的列表中，如果不成功则触发异常处理不会执行任何操作

portScanner_2该函数的参数由目标主机ip，要扫描的端口号，开放的端口列表组成，
该函数的执行过程是为每个要检测的端口建立一个进程，再将这些进程执行，从而大幅
缩短执行的总时间

main函数为程序的主函数，运行时首先获取附加的参数并对其进行处理，确定要扫描的
目标主机ip以及要扫描的端口范围，随后执行portScanner_2函数并导入参数，最后得
输出结果

优化建议：只扫描了tcp服务，可以添加扫描udp服务(DNS域名系统，TFTP简单文件传输
协议，SNMP简单网络管理协议，NTP网络时间协议等等)，没有设置默认扫描的参数，这
就要求用户必须输入-h和-p参数，应该添加默认扫描的端口方便第一次使用的用户
'''
