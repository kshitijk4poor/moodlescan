#!/usr/bin/env python3
#
# moodlescan - Tool for scanning Moodle LMS platforms for vulnerabilities
# Copyright (C) 2025 Victor Herrera - supported by www.incode.cl and CERT-POLSKA
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import moodlescan

def test_update():
	moodlescan.checkupdate()

def test_getuseragent():
	moodlescan.getuseragent()

def test_getheader_01_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://moodle.uam.es/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_02_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://moodle.oulu.fi/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_03_ssl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "http://moodle.sekchile.com/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_03_http():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "http://moodle.sekchile.com/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getheader_01_nossl():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = moodlescan.getignoressl()
	url = "https://moodle.ucl.ac.uk/"
	moodlescan.getheader(url, proxy, agent, ignore)

def test_getversion_01():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = moodlescan.getignoressl()
	url = "https://moodle.ucl.ac.uk/"
	moodlescan.getheader(url, proxy, agent, ignore)
	v = moodlescan.getversion(url, proxy, agent, ignore)
	if v:
		moodlescan.getcve(v)

def test_getversion_02():
	proxy = moodlescan.httpProxy()
	agent = moodlescan.getuseragent()
	ignore = ""
	url = "https://moodle.unizar.es/add/"
	moodlescan.getheader(url, proxy, agent, ignore)
	v = moodlescan.getversion(url, proxy, agent, ignore)
	if v:
		moodlescan.getcve(v)

	
