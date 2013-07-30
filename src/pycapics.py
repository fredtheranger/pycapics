#!/usr/bin/python
# -*- coding: ascii -*-
"""
pycapics.py - Python PCAP Forenics Tool

(30 points) Create a python script that takes a PCAP as input
(30 points) Automatically extracts any JPEG files it finds to an output folder
(10 points) Extract EXIF data for every JPEG file
(5 points ) Calculate MD5 hash of extracted file
(10 points) Input all data into a SQLite database
(5 points ) Produce a .txt report including all information found including MD5
(10 points) Produce a SINGLE KML file for all files extracted that contain LAT/LONG data.

Resources:
- http://code.google.com/p/dpkt/
- Violent Python (TJ O'Connor): Chapter 4: Network Traffic Analysis with Python
- http://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
- https://github.com/catalyst256/PDFHunter/blob/master/pdf-hunter.py

"""
import argparse
import os
import sqlite3
import hashlib
import simplejson
from scapy.all import *
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from simplekml import Kml
from time import gmtime, strftime

### FUNCTIONS ###
def extract_jpgs(pcap, output):
    """
    Extracts the jpeg data from a pcap file.
    Based on https://github.com/catalyst256/PDFHunter/blob/master/pdf-hunter.py
    """

    # Look for content type of image/jpeg and store the TCP ACK
    acks = list()
    for pkt in pcap:
        if pkt.haslayer(Raw):
            if "Content-Type: image/jpeg" in pkt.getlayer(Raw).load:
                acks.append(pkt.getlayer(TCP).ack)
                print "[+] Found image/jpeg with ack of " + str(acks[-1])
    
    # Not the most efficient, but filter through the pkts and find the rest of the 
    # image for each of the ack numbers we captured 
    files = list()       
    for a in acks:
    
        # find all of the packets for this image and save to a list
        segments = pcap.filter(lambda(x): x.haslayer(TCP) and str(x.getlayer(TCP).ack) == str(a))
        image = list()
        for segment in segments:
            if segment.haslayer(Raw):
                image.append(segment.load)
                
        # Now, let's remove the HTTP headers up to the known JPG prefix, 
        # according to http://www.garykessler.net/library/file_sigs.html.
        image = ''.join(image)
        idx = image.index("\xff\xd8\xff")
        image = image[idx:]
          
        # Save the file
        filename = os.path.join(output, str(a) + '.jpg')
        print '[+] Saving ' + filename
        f = open(filename, 'w')
        f.writelines(image)
        f.close()
        files.append(filename)
        
    return files
    
def get_md5(filename):
    """
    Returns a hash of the file provided
    http://stackoverflow.com/questions/1131220/get-md5-hash-of-big-files-in-python
    """
    f = open(filename)
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            
    return md5.hexdigest()
        
def initdb(database):
    """
    Initializes the database and table
    """
    conn = sqlite3.connect(database)
    
    conn.execute("DROP TABLE IF EXISTS results")
    conn.execute("CREATE TABLE results( \
                    filename TEXT PRIMARY KEY NOT NULL, \
                    md5 TEXT NOT NULL, \
                    exif TEXT);" 
                )

    return conn
        
def insert_record(conn, filename, md5, exif):
    """
    Inserts a record into the database
    """
    conn.execute("INSERT INTO results (filename, md5, exif) \
                  VALUES(?, ?, ?)", (filename, md5, exif))
    conn.commit()
    
def extract_exif(conn, image):
    '''
    Helper function to extract the exif from a file
    '''
    exif = None
    if hasattr(image, '_getexif') and hasattr(image._getexif(), 'items'):
        exif = {}
        for k, v in image._getexif().items():
            if k in TAGS:
                decoded = TAGS.get(k, k)
                if decoded == 'GPSInfo':
                    gps = {}
                    for t in v:
                        sub_decoded = GPSTAGS.get(t, t)
                        gps[sub_decoded] = v[t]
                        
                    exif[decoded] = gps
                else:
                    exif[decoded] = v

    if not exif or len(exif) < 1:
        print "[-] No exif data found"
        
    return exif

def convert_to_degrees(value):
    '''
    Helper function to convert the GPS coordinates stored in the EXIF to degress in float format.
    From: http://eran.sandler.co.il/2011/05/20/extract-gps-latitude-and-longitude-data-from-exif-using-python-imaging-library-pil/
    '''
    d0 = value[0][0]
    d1 = value[0][1]
    d = float(d0) / float(d1)
 
    m0 = value[1][0]
    m1 = value[1][1]
    m = float(m0) / float(m1)
 
    s0 = value[2][0]
    s1 = value[2][1]
    s = float(s0) / float(s1)
 
    return d + (m / 60.0) + (s / 3600.0)

def get_lat_long(exif):
    '''
    Extract latitude and longitutde from exif data
    '''
    
    if 'GPSLatitude' in exif:
        latitude = convert_to_degrees(exif['GPSLatitude'])
        if 'GPSLatitudeRef' in exif and exif['GPSLatitudeRef'] != 'N':
            latitude = - latitude
    
    if 'GPSLongitude' in exif:
        longitude = convert_to_degrees(exif['GPSLongitude'])
        if 'GPSLongitude' in exif and exif['GPSLongitude'] != 'E':
            longitude = - longitude
       
    return latitude, longitude
    
### MAIN ###
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="path pcap file")
    parser.add_argument("-o", "--output", help="Output directory (must already exist)", default="./")
    parser.add_argument("-d", "--database", help="Database filename", default="sqlite.db")
    parser.add_argument("-k", "--kml", help="KML filename", default="results.kml")
    parser.add_argument("-r", "--report", help="Report filename", default="report.txt")
    args = parser.parse_args()

    # Check if pcap is a valid file
    if not os.path.exists(args.pcap):
        print "Invalid pcap file. Quitting."
        exit(1)
        
    # Check if output path is a valid file
    if not os.path.exists(args.output):
        print "Invalid output path. Quitting."
        exit(1)

    ### READ PCAP FILE ###
    pcap = rdpcap(args.pcap)
    files = extract_jpgs(pcap, args.output)
    
    ### INITIALIZE DATABASE ###
    conn = initdb(os.path.join(args.output,args.database))
    
    ### INITIALIZE KML ###
    kml = Kml(name=args.kml)
    
    for fname in files:
        
        ### EXTRACT EXIF DATA ###
        print "[+] Extracting exif data from " + fname
        image = Image.open(fname)
        exif = extract_exif(conn, image)
        
        ### GET MD5 ###
        md5hash = get_md5(os.path.basename(fname))
        print "[+] Getting md5 hash for " + os.path.basename(fname) + " => " + md5hash
        
        ### INSERT INTO DATABASE ###
        print "[+] Inserting record into database for " + fname
        insert_record(conn, os.path.basename(fname), md5hash, simplejson.dumps(exif))
        
        ### WRITE GPS INFO TO KML ###
        if exif["GPSInfo"]:
            latitude, longitude = get_lat_long(exif['GPSInfo'])
            print "[+] Writing GPS info (%s, %s) to KML for %s" % (longitude, latitude, os.path.basename(fname))
            descr = '%s, %s' % ( longitude, latitude )
            kml.newpoint(name=os.path.basename(fname),
                        description=descr,
                        coords=[(longitude, latitude)])
        
    ### SAVE KML TO FILE ###
    print "[+] Saving KML file to " + os.path.join(args.output, args.kml)
    kml.save(os.path.join(args.output, args.kml))
    
    ### GENERATE REPORT ###
    print "[+] Generating final report as " + os.path.join(args.output, args.report)
    with open(os.path.join(args.output, args.report), 'w') as r:
        now = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        r.write("<==== Extraction Results ====>\n")
        r.write("Filename: %s\n" % args.pcap)
        r.write("Timestamp: %s GMT \n\n" % now)
        
        for row in conn.execute("SELECT * FROM results"):
            r.write("===================\n")
            r.write("Image: %s\n" % row[0])
            r.write("MD5 Hash: %s\n" % row[1])
            
            if row[2] and row[2] != "null":
                r.write("EXIF data:\n")
                json = simplejson.loads(row[2])
                for i in json:
                    r.write("\t%s: %s\n" % (i, json[i]))
                    if i == "GPSInfo":
                        latitude, longitude = get_lat_long(json['GPSInfo'])
                        r.write("\t%s (translated): %s, %s\n" % (i, latitude, longitude))
            else:
                r.write("No EXIF data found\n")
                        
            r.write("===================\n\n")
        
    conn.close()
    
    
if __name__ == '__main__':
    main()
