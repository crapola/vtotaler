""" VTotaler functions. """

import glob
import hashlib
import os
from typing import BinaryIO

import vt

from api_key import VT_API_KEY


def get_score(obj:vt.Object)->tuple:
	"""
	Get number of threat detections from vt.Object response.
	Return as tuple (malicious count,total).
	"""
	# <vt.Object file> keeps stats in 'last_analysis_stats'.
	# <vt.object analysis> keeps stats in 'stats'.
	stats:dict=obj.get('last_analysis_stats' if obj.type=='file' else 'stats')
	malicious:int=stats['malicious']+stats['suspicious']
	total:int=sum(stats.values())
	return (malicious,total)

def list_files(path:str)->tuple[str,...]:
	"""
	List files at <path>.
	<path> can be a directory, a file, and include patterns.
	Return a list of absolute paths to individual files.
	"""
	if os.path.isdir(path):
		path+="/*"
	return tuple(os.path.abspath(x) for x in glob.glob(path) if not os.path.isdir(x))

def scan(path:str)->None:
	""" Scan files in <path>. """
	assert VT_API_KEY,"VirusTotal API key not set."
	with vt.Client(VT_API_KEY) as vtc:
		files_list:tuple[str,...]=list_files(path)
		if not files_list:
			print(f"Invalid path: {path}")
			return
		bad_files:int=scan_files(vtc,files_list)
		plural:str="s" if bad_files>1 else ""
		messages:tuple[str,...]=(f'{bad_files} potentially unsafe file{plural} found!','all good.')
		print(f"Scan completed, {messages[int(bad_files==0)]}")

def scan_files(vt_client:vt.Client,files_list:tuple[str,...])->int:
	""" Scan files. """
	bad_files_count:int=0
	for file_path in files_list:
		with open(file_path,"rb") as file:
			result:vt.Object|None=vt_get_file(vt_client,file)
			score:tuple
			if result:
				score=get_score(result)
			else:
				score=get_score(vt_scan_file(vt_client,file))
			color:str='\033[91m' if score[0]>0 else '\033[92m'
			score_str:str=f"[{color}{score[0]:2}/{score[1]:2}\033[0m]"
			print(f"{score_str} {file_path}")
			if score[0]>0:
				bad_files_count+=1
	return bad_files_count

def vt_get_file(vt_client:vt.Client,file:BinaryIO)->vt.Object|None:
	"""
	Get file information by checking file hash.
	Return a <vt.Object file>, or None if hash is unknown.
	"""
	try:
		file.seek(0)
		sha256:str=hashlib.sha256(file.read()).hexdigest()
		return vt_client.get_object("/files/"+sha256)
	except vt.APIError as e:
		if e.code=="NotFoundError":
			return None
		raise

def vt_scan_file(vt_client:vt.Client,file:BinaryIO)->vt.Object:
	"""
	Send file for analysis.
	Return <vt.Object analysis>.
	"""
	file.seek(0)
	return vt_client.scan_file(file,True)
