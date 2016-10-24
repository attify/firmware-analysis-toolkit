#!/usr/bin/env python

import sys,os,subprocess

# Put this script in the firmadyne path downloadable from
# https://github.com/firmadyne/firmadyne

#Configurations - change this according to your system
firmadyne_path = '/root/tools/firmadyne'
binwalk_path = '/usr/local/bin/binwalk'
mitm_path = '/usr/bin/mitmdump'

# Debugging and testing purposes

# firm_name = "wnap320.zip"
# firm_brand = "netgear"


def Intro():
	print """
	Welcome to the Firmware Analysis Toolkit - v0.1
	Offensive IoT Exploitation Training  - http://offensiveiotexploitation.com
	By Attify - https://attify.com  | @attifyme
	"""

def do_extract():
	create_dir = 'mkdir ' + extract_path + '/' + str(image_id)
	extract_command = 'cp ' + firmadyne_path + '/images/' + str(image_id) + '.tar.gz ' +  extract_path + str(image_id)
	subprocess.call([create_dir])
	subprocess.call(extract_command)

def delete():
	id_del = int("Which ID to delete")
	delete_command = firmadyne_path + '/scripts/delete.sh ' + id_del
	subprocess.call([delete_command])

def getInfo():
    getInfo.firm_name = str(raw_input("Enter the name or absolute path of the firmware you want to analyse : "))
    getInfo.firm_brand = str(raw_input("Enter the brand of the firmware : "))

def extractor(firm_name,firm_brand):
	print "Now going to extract the firmware. Hold on.."
	extractor_command = firmadyne_path + '/sources/extractor/extractor.py -b ' + firm_brand + ' -sql 127.0.0.1 -np -nk ' + "\""+ firm_name + "\"" + " images "
	print str(extractor_command)
	output = subprocess.check_output(extractor_command, shell=True)
	output_new = output.split('\n')
	extractor.data_id = ""
	for line in output_new:
		if "Database"in line:
			data_id = line[-1:]
			print "test"
			print "The database ID is " + str(data_id)
			extractor.data_id = data_id

def get_image_type(image_id):
	print "Getting image type"
	get_image_type_command = firmadyne_path + "/scripts/getArch.sh ./images/" + str(image_id) + ".tar.gz"
	output = subprocess.check_output(get_image_type_command, shell=True)
	actual_image_type = output.split('\n')[0].split(':')[1]
	print "Found image type of " + str(actual_image_type)

def tar2db_and_makeImage(image_id):
	print "Putting information to database"
	try:
		tar2db_command = firmadyne_path + "/scripts/tar2db.py -i " + str(image_id) + " -f " + firmadyne_path + "/images/" + str(image_id) + ".tar.gz"
		output_tar = subprocess.check_output(tar2db_command, shell=True)
		print "Tar2DB" + str(output_tar)
	except:
		print "Already done earlier"
	try:
		print "Creating Image"
		makeImage_command = "sudo " + firmadyne_path + "/scripts/makeImage.sh " + str(image_id)
		print "Executing command \n"
		print str(makeImage_command)
		output_makeImage = subprocess.check_output(makeImage_command, shell=True)
		print "Make Image output " + str(output_makeImage)
	except:
		print "Please check the makeImage function"

def network_setup(image_id):
	print "Setting up the network connection"
	network_cmd = 'sudo ' + firmadyne_path + "/scripts/inferNetwork.sh " + str(image_id)
	output = subprocess.check_output(network_cmd, shell=True)
	print output

def final_run(image_id):
	print "Running the firmware finally : "
	final_run_cmd = 'sudo ' + firmadyne_path + "/scratch/" + str(image_id) + "/run.sh"
	print subprocess.check_output(final_run_cmd, shell=True)

def final(image_id):
	print "Everything is done for the image id " + str(image_id)

def main():
	Intro()
	getInfo()
	print getInfo.firm_name
	firm_name = getInfo.firm_name
	firm_brand = getInfo.firm_brand
	extractor(firm_name,firm_brand)
	image_id = str(extractor.data_id)
	if image_id == "":
		print "Something went wrong"
	else:
		get_image_type(image_id)
		tar2db_and_makeImage(image_id)
		final(image_id)
		network_setup(image_id)
		final_run(image_id)


if __name__ == '__main__':
    main()
