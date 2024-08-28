""" Command line scan. """
import sys

import vtotaler

if vtotaler.VT_API_KEY!="":
	if len(sys.argv)>1:
		d:str=sys.argv[1]
		vtotaler.scan(d)
	else:
		print("Please provide a path.")
else:
	print("API key not set in api_key.py")
