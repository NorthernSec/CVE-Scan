#!/usr/bin/env python3.3
# -*- coding: utf8 -*-
#
# Read input from NMap and use the information from cve-search to find
#  potential vulnerabilities in the recognized systems and their services

# Copyright (c) 2015-2017  NorthernSec
# Copyright (c)	2015-2017  Pieter-Jan Moreels
# This software is licensed under the Original BSD License

# Imports
import argparse
import json
import os
import sys

runpath=os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runpath, '..'))

from datetime       import datetime

from bin.converter import parseNMap
from lib.Config    import Configuration
from lib.Toolkit   import writeJson, queryAPI

def enhance(scan):
  for system in scan['systems']:
    cpe=system['cpes'] if 'cpes' in system else None
    if cpe:
      cpes=[]
      for c in cpe:
        try:
          c = c.lower()
          cpes.append({'cpe': c, 'cves': queryAPI(c)})
        except Exception as e:
          print(e)
          pass
      system['cpes']=cpes
      #TODO get possible dpe info and store in dpe
    for service in system['services']:
      if 'cpe' in service:
        try:
          service['cves']=queryAPI( service['cpe'].lower() )
        except Exception as e:
          print(e)
          pass
      #TODO get dpe info for service
  scan['enhanced']={"time": int(datetime.now().strftime('%s'))}
  return scan


if __name__ == '__main__':
  # argument parser
  description='''Read input from NMap and use the information from
                 cve-search to find potential vulnerabilities in the
                 recognized systems and their services'''
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument('-j', metavar='json',   type=str, help='Read Json file in Nmap2CVE format' )
  parser.add_argument('-x', metavar='xml',    type=str, help='Read NMap XML file' )
  parser.add_argument('out', metavar='output', type=str, help='Output file')
  args = parser.parse_args()

  # input
  if not args.x and not args.j: sys.exit("No input selected!")
  if args.x:
    syslist=parseNMap(file=args.x)
  elif args.j:
    try:
      syslist=json.loads(open(args.j).read())
    except:
      sys.exit("Invalid JSon format!")
  #output

  #CVE-Scan magic
  try:
    syslist=enhance(syslist)
    writeJson(args.out, syslist)
  except Exception as e:
    print(e)
    sys.exit("Could not connect to the CVE-Search API on %s:%s"%(Configuration.getCVESearch()))
