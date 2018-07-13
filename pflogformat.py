import re

#Path-Logfile
file = '/var/log/pflog.txt'
file2= '/var/log/canaryfw.log'

#Regexpression
searchstring ='(?P<date>\w+\s\S+\s\d+:\d+:\d+).+?(?=])]\spass\s\S+\son\s(?P<IN>\w+):\s(?P<SRC>\d+.\d+.\d+.\d+).(?P<SPT>\d+)\s>\s(?P<DST>\d+.\d+.\d+.\d+).(?P<DPT>\d+):\s(?P<FLG>\S+).+?(?=win)win\s(?P<WINDOW>\d+)\s.+?(?=\()\(ttl\s(?P<TTL>$



#Open logfile
with open(file) as f:
    for line in f:
        #Search with regexpression
        result=re.search(searchstring,line)
        #Format pf -> opencanary
        if result:
            date = result.group('date')
            interface = result.group('IN')
            sourceIP = result.group('SRC')
            sourcePT = result.group('SPT')
            destIP = result.group('DST')
            destPT = result.group('DPT')
            flag = result.group('FLG')
            window = result.group('WINDOW')
            ttl = result.group('TTL')
            id = result.group('ID')
            length = result.group('LEN')

            res2 ="canaryfw: "+date+" IN="+interface+" SRC="+sourceIP+" DST="+destIP+" LEN="+length+" TTL="+ttl+" ID="+id+" SPT="+sourcePT+" DPT="+destPT+" WINDOW="+window+"\n"
            with open(file2,"a") as myfile:
                myfile.write(res2)
                myfile.close()
