#!/usr/bin/env python
# testconn.py - python 2.7

import string
from struct import *
from socket import *
from sys import stderr, stdout, stdin

class Empty(object):
    pass

def command(com,data):
    msg = ""
    if com == "lookup":
      msg += "\x00"  
    elif com == "commit":
        msg += "\x01"
    elif com == "create":
        msg += "\x02"
    elif com == "transfer":
        msg += "\x03"
    else:
        stderr.write("bad command\n")
        return ""

    if com == "transfer":
        if not hasattr(data,"src") or not hasattr(data,"dst"):
            stderr.write("missing src or dst for transfer\n")
            return ""
        msg += "\x06" + pack(str(len(data.src)+1)+"s",data.src)
        msg += "\x07" + pack(str(len(data.dst)+1)+"s",data.dst)
    else:
        if not hasattr(data,"key"):
            stderr.write("missing key property\n")
            return ""
        msg += "\x00" + pack(str(len(data.key)+1)+"s",data.key)
        if hasattr(data,"user"):
            msg += "\x02" + pack(str(len(data.user)+1)+"s",data.user)
        if hasattr(data,"id"):
            msg += "\x01" + pack("<i",int(data.id))
        if hasattr(data,"display"):
            msg += "\x03" + pack(str(len(data.display)+1)+"s",data.display)
        if hasattr(data,"expire"):
            msg += "\x04" + pack("<q",int(data.expire))
        if hasattr(data,"redirect"):
            msg += "\x05" + pack(str(len(data.redirect)+1)+"s",data.redirect)
        if hasattr(data,"tag"):
            msg += "\x08" + pack(str(len(data.tag)+1)+"s",data.tag)

    msg += "\xff"
    return msg

def extract_string(src,it):
    st = it
    while it < len(src) and src[it] != "\x00":
        it += 1
    return src[st:it]

def print_response(response):
    type = response[0]
    if type == "\x00":
        # message: just read a null terminated string
        print response[1:len(response)-1]
    elif type == "\x01":
        # error: functionally this behaves just like message
        print response[1:len(response)-1]
    elif type == "\x02":
        # record: parse fields
        i = 1
        while i < len(response):
            fieldNo = response[i]
            i += 1
            t = "null"
            if fieldNo == "\x00":
                t = "string"
                s = "  key: "
            elif fieldNo == "\x01":
                t = "int"
                s = "  id: "
            elif fieldNo == "\x02":
                t = "string"
                s = "  user: "
            elif fieldNo == "\x03":
                t = "string"
                s = "  display: "
            elif fieldNo == "\x04":
                t = "long"
                s = "  expire: "
            elif fieldNo == "\x05":
                t = "string"
                s = "  redirect: "
            elif fieldNo == "\x06":
                t = "string"
                s = "  transsrc: "
            elif fieldNo == "\x07":
                t = "string"
                s = "  transdst: "
            elif fieldNo == "\x08":
                t = "string"
                s = "  tag: "
            elif fieldNo == "\xff":
                break

            if t == "string":
                ss = extract_string(response,i)
                i += len(ss) + 1
                s += ss
            elif t == "int":
                ss = response[i:i+4]
                i += 4
                s += str(unpack("<i",ss)[0])
            elif t == "long":
                ss = response[i:i+8]
                i += 8
                s += str(unpack("<q",ss)[0])

            print s

addr = "\0uniauth"
sock = socket(AF_UNIX,SOCK_STREAM)
sock.connect(addr)

while True:
    print "command:"
    com = stdin.readline()
    if len(com) == 0:
        break;
    com = com.strip()
    data = Empty()
    print "fields:"
    while True:
        line = stdin.readline()
        if len(line) == 0:
            break
        line = line.strip()
        parts = map(lambda s: s.strip(),line.split(':'))
        if len(parts) != 2:
            stderr.write("too many parts in field string - try again")
            continue
        setattr(data,*parts)
    msg = command(com,data)
    if len(msg) == 0:
        continue
    print "wrote bytes:", msg.encode('hex')
    print "wrote", sock.send(msg), "bytes"

    response = sock.recv(4096)
    print "received", response.encode('hex')
    print "received", len(response), "bytes"
    print_response(response)
    print "-" * 80
