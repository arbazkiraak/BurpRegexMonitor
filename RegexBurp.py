from burp import IBurpExtender,IHttpListener,IScannerCheck,IScanIssue
from array import array
import jarray
import re,threading,Queue

###! TODO ADD THREADING :
#1. Add Threading for speed.

final_issues = []
main_queue = []
with open('exceptions_list.txt','r') as f:
	for i in f.readlines():
		i = i.strip()
		if i not in main_queue:
			main_queue.append(re.escape(str(i)))


class CustomScanIssue(IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService


class BurpExtender(IBurpExtender,IHttpListener):
	def registerExtenderCallbacks(self,callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("RegexMonitorExtension")
		callbacks.registerHttpListener(self)
		self.CheckBugs()

	def CheckBugs(self):
		if final_issues:
			org_final_issues = final_issues[:]
			del final_issues[:]
			for each_issue in org_final_issues:
				print("[**********] Regex PASSIVE ISSUES DETECTED [*************]")
				self._callbacks.addScanIssue(each_issue)
		self.check_bugs_thread = threading.Timer(10,self.CheckBugs).start()

	def bts_safe(self,bytes):
		if bytes is None: bytes = ''
		return self._helpers.bytesToString(bytes)

	def overlap_array_checker(self,array_of_matches):
		if array_of_matches:
			array_of_matches.sort(key=lambda interval: interval[0])
			merged = [array_of_matches[0]]
			for current in array_of_matches:
				previous = merged[-1]
				if current[0] <= previous[1]:
					previous[1] = max(previous[1], current[1])
				else:
					merged.append(current)
			if merged:
				merged.sort()
				return merged
			else:
				print('[ERROR]: There is an problem at overlap_array_checker , NO MATCH')
		else:
			print('[ERROR]: There is no Array of Matches while checking overlap_array_checker on')
			return [array('i',[0,1])]


	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		if toolFlag in [1024,32,16,8,64,1,2]:
			if not messageIsRequest:
				msg = messageInfo.getResponse()
				_RES_INFO = self._helpers.analyzeRequest(messageInfo.getHttpService(),messageInfo.getResponse())
				self._URL = _RES_INFO.getUrl()
				msg_str = self.bts_safe(msg)
				matches_array = self.CheckExceptionsMain(msg,msg_str,toolFlag)
				if matches_array != False:
					matches_array = self.overlap_array_checker(matches_array)
					httpmsg = [self._callbacks.applyMarkers(messageInfo,None,matches_array)]
					detail = "Request was generated from : {} TOOL".format(str(toolFlag))
					final_issues.append(CustomScanIssue(messageInfo.getHttpService(),_RES_INFO.getUrl(),httpmsg,"Regex DETECTED",detail,"Low"))
				else:
					pass 
			else:
				pass
		else:
			pass


	def CheckExceptionsMain(self,msg,msg_str,toolflag):
		temp_remove_dups = []
		matches_array = []
		if main_queue:
			for each_regex in main_queue:
				try:
					regex = re.compile(each_regex,re.MULTILINE|re.IGNORECASE)
					re_r = re.finditer(regex,msg_str)
				except Exception as e:
					print("[EXCEPTION] At Regex Compiling : {} : {}".format(str(e),each_regex))
					return False
				reslen = len(msg_str)
				try:
					re_r = list(set([str(x.group()) for x in re_r]))
				except UnicodeEncodeError:
					re_r = list(set([x.group().encode('utf-8') for x in re_r]))
				if re_r:
					print("[LOOT] Reflection Found for : {} at {} : {}".format(str(self._URL),str(re_r),str(toolflag)))
					for match in re_r:
						if match not in temp_remove_dups:
							start = 0
							matchlen = len(match)
							while start < reslen:
								start = self._helpers.indexOf(msg_str,match,True,start,reslen)
								if start != -1:
									final_offset = array('i',[start,start+matchlen])
									if final_offset not in matches_array:
										matches_array.append(final_offset)
										temp_remove_dups.append(match)
										start += matchlen
									else: ###! Recently Added this to break it from preventing `while infinite loop`
										break
								else:
									break

		if matches_array:
			matches_array.sort()
			return matches_array
		else:
			return False
