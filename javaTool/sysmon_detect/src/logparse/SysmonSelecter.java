package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Detect mimikatz comparing Common DLL List with exported Sysmon event log.
 * Output processes that load all DLLs in Common DLL List and detection rate.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class SysmonSelecter {

	 /**
	 * Specify file name of mimikatz
	 */
	private static final String MIMIKATZ_MODULE_NAME = "powershell.exe";
	private static Map<Integer, HashSet> log;
	private static Map<Integer, HashSet> realLog=new HashMap<Integer, HashSet>();
	private static HashSet<String> commonDLLlist = new HashSet<String>();
	private static String commonDLLlistFileName = null;
	private static String outputDirName = null;
	private static int falsePositiveCnt = 0;
	private static int falseNegativeCnt = 0;

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int processId = 0;
			String date="";
			String image="";
			String imageLoaded ="";
			HashSet<String> realLogLine=new HashSet<String>();
			
			String concatLine="";
			while ((line = br.readLine()) != null) {
				concatLine+=line+"\n";
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (elem.startsWith("ProcessId:")) {
						processId = Integer.parseInt(parseElement(elem,": "));
					} else if (elem.startsWith("Image:")) {
						image=parseElement(elem,": ");
					}
					if (elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
						imageLoaded = parseElement(elem,": ");
						HashSet<EventLogData> evSet;
						if (null == log.get(processId)) {
							evSet=new HashSet<EventLogData>();
						} else {
							evSet = log.get(processId);
						}
						evSet.add(new EventLogData(date,imageLoaded,image));
						log.put(processId, evSet);
					}
					else if (elem.startsWith("SignatureStatus:")) {
						if(null!=realLog.get(processId)){
							realLogLine=realLog.get(processId);
							
						}
						realLogLine.add(concatLine);
						realLog.put(processId, realLogLine);
						concatLine="";
						realLogLine=new HashSet<String>();
					}
				}
				
			}
			br.close();

		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter) {
		String value="";
		try{
		String elems[] = elem.split(delimiter);
		value = elems[1].trim();
		}catch (RuntimeException e){
			e.printStackTrace();
		}
		return value;
	}

	private void outputLoadedDLLs(Map map, String outputFileName) {
		File file = new File(outputFileName);
		String filename=file.getName();
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);

			for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
				Map.Entry<Integer, HashSet> entry = (Map.Entry<Integer, HashSet>) it.next();
				Object processId = entry.getKey();
				HashSet<EventLogData> evs = (HashSet<EventLogData>) entry.getValue();
				HashSet<String> imageLoadedList = new HashSet<String>();
				for (EventLogData ev: evs) {
					imageLoadedList.add(ev.getImageLoaded());
				}
				boolean result = isMatchWithCommonDLLlist(commonDLLlistFileName, imageLoadedList);
				if(result){
					HashSet<String> lines=realLog.get(processId);
					for (String line : lines) {
						pw.println(line);
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private boolean isMatchWithCommonDLLlist(String commonDLLlistFileName, HashSet<String> imageLoadedList) {
		boolean result = false;
		for(String dll:commonDLLlist){
			if(imageLoadedList.contains(dll)){
				result=true;
				break;
			};
		}
		return result;
	}

	/**
	* Parse CSV files exported from Sysmon event log.
	* Output process/loaded DLLs and detect which matches Common DLL List.
	* @param inputDirname 
	*/
	public void outputLoadedDlls(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
				outputLoadedDLLs(log, this.outputDirName + "/" + filename);
			} else {
				continue;
			}
		}

	}

	private void readCommonDLLList() {
		BufferedReader br = null;
		try {
			File f = new File(commonDLLlistFileName);
			br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				String dll = line.trim();
				commonDLLlist.add(dll);
			}
		} catch (IOException e) {
			System.out.println(e);
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println("{iputdirpath} {Common DLL List path} {outputdirpath} (-dr)");
		System.out.println("If you evaluate detection rate using Common DLL Lists specify -dr option.)");
	}

	public static void main(String args[]) {
		SysmonSelecter sysmonParser = new SysmonSelecter();
		String inputdirname="" ;
		if (args.length < 3) {
			printUseage();
		} else if (args.length > 0) {
			inputdirname = args[0];
		}
		if (args.length > 1) {
			commonDLLlistFileName = args[1];
		}
		if (args.length > 2) {
			outputDirName = args[2];
		}
		log = new HashMap<Integer, HashSet>();
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.readCommonDLLList();
		sysmonParser.outputLoadedDlls(inputdirname);

	}

}
