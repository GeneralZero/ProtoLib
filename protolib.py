import string, datetime, re

from struct import unpack, pack

class Protobuf(object):
	"""docstring for ProtobufEncode"""
	def __init__(self, fileName="", raw="", depth=0, offset=0):
		self.parsePos = 0
		self.length = 0
		self.returndata = []
		self.depth = depth
		self.offset = offset

		if fileName != "":
			self.binary = self.getBinaryfromFile(fileName)
			self.parseProtobuf()

		elif raw != "":
			self.binary = raw
			self.parseProtobuf()
		

	def getBinaryfromFile(self, fileName):
		"""Reads Binary from file and stores it in returns a binary string"""
		return fileName.read()

	def output2Bin(self, protoList=None):
		""" Takes information in self.returndata and converts it to a binary string used for sending out data"""
		if protoList == None:
			protoList = self.returndata

		outbin = ""

		for elements in protoList:
			for x in elements:
				if type(elements[x]) == unicode:
					elements[x] = elements[x].encode('utf-8')

			if type(elements['data']) is list:
				outbin += self._outputHeader(elements['messageId'], self.getTypefromName(elements['datatype']))
				rec = self.output2Bin(elements["data"])
				if len(rec) <= 1:
					outbin += self._outputVarint(1)
				else:
					outbin += self._outputVarint(len(rec))
				outbin += rec

			else:
				if elements['datatype'] == "Varint":
					#if elements['subtype'] == 'Unix Timestamp':
					#	pass

					#if type(elements["data"]) == str:
					#	elements["data"] = int(elements["data"])
						
					outbin += self._outputHeader(elements['messageId'], self.getTypefromName(elements['datatype']))
					outbin += self._outputVarint(elements["data"])

				elif elements['datatype'] == "64-bit":
					#if type(elements["data"]) == str:
					#	elements["data"] = int(elements["data"])

					outbin += self._outputHeader(elements['messageId'], self.getTypefromName(elements['datatype']))
					outbin += self._output64Bit(elements["data"])

				elif elements['datatype'] == "Length-delimited":
					outbin += self._outputHeader(elements['messageId'], self.getTypefromName(elements['datatype']))
					outbin += self._outputVarint(len(elements["data"]))
					outbin += self._outputLengthDelimited(len(elements["data"]), elements["data"])

				elif elements['datatype'] == "32-bit":
					#if type(elements["data"]) == str:
					#	elements["data"] = int(elements["data"])

					outbin += self._outputHeader(elements['messageId'], self.getTypefromName(elements['datatype']))
					outbin += self._output32Bit(elements["data"])

				else:
					raise Exception("Invalid datatype %d" % datatype)

		return outbin

	def parseProtobuf(self):
		"""Takes information from self.binary and parses the binary to a list stored in self.returndata"""
		currentType = -1
		feildType = -1

		while self.parsePos < len(self.binary):
			if currentType == -1:
				(feildType, currentType) = self._parseProtobufHeader()

				#Sanity Check for CurrentType
				name = self.getNameofType(currentType)

			#Varint
			elif currentType == 0:
				self._parseVarint(feildType)
				currentType = -1

			#64-bit
			elif currentType == 1:
				self._parse64Bit(feildType)
				currentType = -1

			#Length-delimited
			elif currentType == 2:
				try:
					self._parseLengthDelimited(feildType)
				except Exception as e:
					raise Exception("Invalid Recursive Message: %s" % e.message)

				currentType = -1
			
			#32-bit
			elif currentType == 5:
				self._parse32Bit(feildType)
				currentType = -1

			else:
				raise Exception("Invalid Message Type")

	def updateReturnData(self, messageid, length, datatype, data, subtype=''):
		"""Helper function used to store object data in self.returndata"""
		datatype = self.getNameofType(datatype)
		if subtype == '':
			self.returndata.append({"datatype":datatype, "data":data, "length":length, "messageId":messageid})

		else:
			self.returndata.append({"datatype":datatype, "data":data, "length":length, "messageId":messageid, "subtype":subtype})

	def getNameofType(self, datatype):
		"""String version of the types for Protobuf """
		if datatype == 0:
			return "Varint"

		elif datatype == 1:
			return "64-bit"

		elif datatype == 2:
			return "Length-delimited"

		elif datatype == 5:
			return "32-bit"

		else:
			raise Exception("Invalid datatype %d" % datatype)


	def getTypefromName(self, dataname):
		"""Intager version of the types for Protobuf """
		if dataname == "Varint":
			return 0

		elif dataname == "64-bit":
			return 1

		elif dataname == "Length-delimited":
			return 2

		elif dataname == "32-bit":
			return 5

		else:
			raise Exception("Invalid datatype %d" % datatype)

	def _parseProtobufHeader(self):
		"""Parse the Header block of the current possition of the binary data
		    ________________
			|1|2|3|4|5|6|7|8|
			-----------------
			1 is contunue bit
			2-5 is the feild type
			6-8 is the wire type
		"""
		feildType = []
		tempParsePos = self.parsePos
		byte = self.getByte(tempParsePos)

		cont = (((0x01 << 7) & byte) >> 7)
		feildType.append(((0x0f << 3) & byte) >> 3)
		currentType = 0x07 & byte
		tempParsePos += 1

		while cont == 1:
			if tempParsePos >= len(self.binary):
				return -1, -1

			byte = self.getByte(tempParsePos)
			cont = (((0x01 << 7) & byte) >> 7)
			feildType.append((0x7F & byte))
			tempParsePos += 1

		fullint = 0

		for x in reversed(feildType):
			fullint <<= 7
			fullint += x

		self.parsePos = tempParsePos
		return fullint, currentType

	def _outputHeader(self, feildType, wireType):
		"""Output the Header block of with the arguments feildtype and wiretype
		    ________________
			|1|2|3|4|5|6|7|8|
			-----------------
			1 is contunue bit
			2-5 is the feild type
			6-8 is the wire type
		"""
		if feildType >= 0:
			if wireType >= 0 and wireType <= 5:
				cont = 1
				bitList = []
				binstr = ""

				while feildType > 0:
					bitList.append((0x0f & feildType))
					feildType >>= 4

				for x in xrange(0,len(bitList)):
					if x == len(bitList)-1:
						cont = 0

					else:
						cont = 1

					bits = ((cont<< 4) + bitList[x]) << 3
					
					if x == 0:
						bits += wireType

					else:
						pass

					binstr += pack('B', bits)

				return binstr

			else:
				raise Exception("Invalid WireType %d " % wireType)

		else:
			raise Exception("Invalid FeildType %d " % feildType)


	def _parse32Bit(self, feildType):
		"""32 bits of binary data in little-endian byte order. Returns the intager and float versions because you dont know what it is. """
		bin_data = pack('>I', self.getByte(self.parsePos, 4))
		intager = unpack('<i', bin_data)
		nonintager = unpack('<f', bin_data)

		self.parsePos += 4

		self.updateReturnData(feildType, 4, 5, intager[0])

	def _output32Bit(self, uint):
		return pack("<i", uint)

	def _parse64Bit(self, feildType):
		"""64 bits of binary data in little-endian byte order. Returns the intager and float versions because you dont know what it is."""
		bin_data = pack('>Q', self.getByte(self.parsePos, 8))
		intager = unpack('<q', bin_data)
		nonintager = unpack('<d', bin_data)

		self.parsePos += 8

		self.updateReturnData(feildType, 8, 1, intager[0])

	def _output64Bit(self, uint):
		return pack("<q", uint)

	def _parseVarint(self, feildType):
		"""Parse the Varint and returns the 
		    ________________
			|1|2|3|4|5|6|7|8|
			-----------------
			1 is contunue bit
			2-8 is the 7byte int
		"""
		newInt = []
		cont = 1

		while cont == 1:
			byte = self.getByte(self.parsePos)
			cont = (((0x01 << 7) & byte) >> 7)
			newInt.append((0x7F & byte))
			self.parsePos += 1

		uint = 0
		for x in reversed(newInt):
			uint <<= 7
			uint += x

		signed = hex(uint)
		if uint < 2147483647:
			signed = (uint << 1) ^ (uint >> 31)

		elif uint < 9223372036854775807:
			signed = (uint << 1) ^ (uint >> 63)

		#Try to guess if it is a time stamp
		if 1400000000 < uint and 1550000000 > uint:
			#ctime = datetime.datetime.fromtimestamp(uint).strftime('%Y-%m-%d %H:%M:%S')
			self.updateReturnData(feildType, len(newInt), 0, uint, "Unix Timestamp")
        
        #Try to guess if it is a time stamp in ms    
		elif 1400000000000 < uint and 1550000000000 > uint:
			#ctime = datetime.datetime.fromtimestamp(uint/1000).strftime('%Y-%m-%d %H:%M:%S')
			self.updateReturnData(feildType, len(newInt), 0, uint, "Unix Timestamp")

		else:
			self.updateReturnData(feildType, len(newInt), 0, uint)


	def _outputVarint(self, varint):
		"""Parse the Varint and returns the 
		    ________________
			|1|2|3|4|5|6|7|8|
			-----------------
			1 is contunue bit
			2-8 is the 7byte int
		"""
		bitList = []

		bitList.append(0x7F & varint)
		varint >>= 7

		while varint > 0:
			bitList.append(0x7F & varint)
			varint >>= 7
			
		binstr = ""

		for x in xrange(0,len(bitList)):
			if x == len(bitList)-1:
				cont = 0

			else:
				cont = 1

			bits = (cont<< 7) + bitList[x]
			binstr += pack('B', bits)

		return binstr

	def _parseLengthDelimited(self, feildType):
		"""Parse length delimited object could be a string, a recursive object or binary data.
		"""
		newInt = []
		cont = 1

		while cont == 1:
			byte = self.getByte(self.parsePos)
			cont = (((0x01 << 7) & byte) >> 7)
			newInt.append((0x7F & byte))
			self.parsePos += 1

		fullint = 0
		for x in reversed(newInt):
			fullint <<= 7
			fullint += x

		if fullint <= len(self.binary):
			try:
				#Test to see if its a header
				tempParsePos = self.parsePos
				(temp1, temp2) = self._parseProtobufHeader()
				self.parsePos = tempParsePos

				#Is Printable Characters ASCII
				if(all(c in string.printable for c in self.binary[self.parsePos:self.parsePos+fullint])):
					self.updateReturnData(feildType, fullint, 2, self.binary[self.parsePos:self.parsePos+fullint], "ASCII")

				#Try to decode as Recursice Object
				elif temp1 != -1 and temp2 != -1 :
					test = Protobuf(raw=self.binary[self.parsePos:self.parsePos+fullint], depth=self.depth+1, offset=self.offset+self.parsePos)
					self.updateReturnData(feildType, fullint, 2, test.returndata)

			except Exception as e:
				print e.message
				print self.depth, self.offset

				# Is Printable Characters Unicode
				try:
					self.updateReturnData(feildType, fullint, 2, unicode(self.binary[self.parsePos:self.parsePos + fullint], 'utf-8'), "UTF-8")
				except:
					# If not the others then its a binary string.
					self.updateReturnData(feildType, fullint, 2, self.binary[self.parsePos:self.parsePos + fullint].encode('hex'), "Binary")

			self.parsePos += fullint

		else:
			raise Exception("Index Error %d, max length: %d " % (fullint, len(self.binary)))

	def _outputLengthDelimited(self, length, data):
		return data

	def getByte(self, index, length=1):
		""" Helper function to get a subset of the protobuf binary data."""
		if length > 1:
			if index+length < len(self.binary):
				return int(self.binary[index:index+length].encode('hex'), 16)

			else:
				raise Exception("Index is greater than length %d " % index)

		else:
			if index < len(self.binary):
				return int(self.binary[index].encode('hex'), 16)

			else:
				raise Exception("Index is greater than length %d " % index)

	def prettyPrint(self, offset="", root=None, simple=False):
		""" Prints the parced data in a easy viewable form"""
		if root == None:
			root = self.returndata

		strs = ""

		for elements in root:
			if type(elements['data']) is list:
				if simple:
					strs += "%s[\n" % (offset)
					strs += self.prettyPrint((offset + "\t"),elements['data'], simple=simple)
					strs += "%s]" % (offset)

				else:
					strs += "%s[ \"length\": %d\n" % (offset, elements["length"])
					strs += self.prettyPrint((offset + "\t"),elements['data'], simple=simple)
					strs += "%s]" % (offset)

			else:
				if simple:
					if elements.get('subtype'):
						strs += "%s{\"data\": \"%s\", \"datatype\": \"%s\", \"subtype\": \"%s\"}" % (offset, elements['data'], elements['datatype'], elements['subtype'])
					else:
						strs += "%s{\"data\": \"%s\", \"datatype\": \"%s\"}" % (offset, elements['data'], elements['datatype'])

				else:
					strs += offset + str(elements)

			if elements != root[-1]:
				strs += ",\n"

			else:
				strs +="\n"

		return strs

	def mergeNewData(self, newJSON, root=None):
		"""Check number of elements and datatype of the elements then merge the new data and return"""
		if root == None:
			root = self.returndata

		ret = root

		if type(root) is list:
			if len(root) == len(newJSON):
				for index, elements in enumerate(root):
					ret[index] = self.mergeNewData(newJSON[index], root[index])
			else:
				raise Exception("Protobuf diffrent number of elements")

		elif type(root["data"]) == list:
			if len(root["data"]) == len(newJSON):
				for index, elements in enumerate(root["data"]):
					ret["data"][index] = self.mergeNewData(newJSON[index], root["data"][index])
			else:
				print "Protobuf diffrent number of elements"

		
		else:
			if root["datatype"] != newJSON["datatype"]:
				print "Datatype has changed"
			#Replace with the correct type
			elif type(root["data"]) == int and root["data"] != int(newJSON["data"]):
				print "Changed data:", root["data"], " to ", newJSON["data"]
				ret["data"] = int(newJSON["data"])
			elif type(root["data"]) == long and root["data"] != long(newJSON["data"]):
				print "Changed data:", root["data"], " to ", newJSON["data"]
				ret["data"] = long(newJSON["data"])
			elif type(root["data"]) == str and root["data"] != str(newJSON["data"]):
				print "Changed data:", root["data"], " to ", newJSON["data"]
				ret["data"] = str(newJSON["data"])
			elif type(root["data"]) == unicode and root["data"] != newJSON["data"]:
				print "Changed data:", root["data"], " to ", newJSON["data"]
				ret["data"] = newJSON["data"]

		return ret

	def raw_Decode(self, offset="", root=None):
		""" Returns a string in the format that is used by protoc --raw_decode""" 
		if root == None:
			root = self.returndata

		strs = ""

		for elements in root:
			if type(elements['data']) is list:
				strs += "%s%d [" % (offset, elements['messageId'])
				self.raw_Decode((offset + "  "),elements['data'])
				strs += "%s]" % (offset)
			elif type(elements['data']) is str:
				strs += "%s%d: \"%s\"" % (offset, elements['messageId'], elements['data'])
			else:
				strs += "%s%d: %s" % (offset, elements['messageId'], elements['data'])

		return strs

if __name__ == '__main__':
	p = Protobuf()
	print "test"
	print p._outputVarint(151).encode("hex")
