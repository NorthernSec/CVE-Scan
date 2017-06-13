#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Read configuration file or return default values
#
# Copyright (c) 2015	NorthernSec
# Copyright (c)	2015	Pieter-Jan Moreels
# This software is licensed under the Original BSD License

# Imports
import os
runpath=os.path.dirname(os.path.realpath(__file__))

import configparser

class Configuration():
  cp=configparser.ConfigParser()
  cp.read(os.path.join(runpath, '../etc/configuration.ini'))
  default={'flaskHost': '127.0.0.1', 'flaskPort': 5050,
           'flaskDebug': True,
           'cve-searchHost':'localhost', 'cve-searchPort':5000,
           'cve-searchSSL': False}

  @classmethod
  def read(cls, section, item, default):
    result=default
    try:
      if type(default) == bool:
        result=cls.cp.getboolean(section, item)
      elif type(default) == int:
        result=cls.cp.getint(section, item)
      else:
        result=cls.cp.get(section,item)
    except:
      pass
    return result

  # Flask
  @classmethod
  def getFlaskHost(cls):
    return cls.read('Webserver','Host',cls.default['flaskHost'])
  @classmethod
  def getFlaskPort(cls):
    return cls.read('Webserver','Port',cls.default['flaskPort'])
  @classmethod
  def getFlaskDebug(cls):
    return cls.read('Webserver','Debug',cls.default['flaskDebug'])

  # CVE-Search
  @classmethod
  def getCVESearch(cls):
    h=cls.read('CVE-Search', 'Host', cls.default['cve-searchHost'])
    p=cls.read('CVE-Search', 'Port', cls.default['cve-searchPort'])
    return (h,p)

  @classmethod
  def getCVESearchSSL(cls):
    return cls.read('CVE-Search', 'SSL', cls.default['cve-searchSSL'])
