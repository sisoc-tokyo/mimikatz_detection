package logparse;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.collections4.*;

/**
 * Parse CSV files exported from Sysmon event log. Output DLLs loaded by
 * mimikatz and Create Common DLL List.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class SysmonParser {
	/**
	 * Specify file name of mimikatz
	 */
	private static final String MIMIKATZ_MODULE_NAME = "mimikatz.exe";
	private static Map<Integer, HashSet<String>> log;
	private HashSet<String> imageLoadedList;

	private void readCSV(String filename) {
		log = new HashMap<Integer, HashSet<String>>();
		BufferedReader br = null;
		try {
			File f = new File(filename);
			br = new BufferedReader(new FileReader(f));
			String line;
			int processId = 0;
			String image = "";
			while ((line = br.readLine()) != null) {
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (elem.startsWith("ProcessId:")) {
						// Get process ID
						processId = Integer.parseInt(parseElement(elem));
					} else if (elem.startsWith("Image:")) {
						// Get process name
						image = parseElement(elem);
					} else if (elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
						// Get Dll name
						String imageLoaded = parseElement(elem);
						if (image.contains(MIMIKATZ_MODULE_NAME)) {
							if (null == log.get(processId)) {
								imageLoadedList = new HashSet<String>();
							} else {
								imageLoadedList = log.get(processId);
							}
							imageLoadedList.add(imageLoaded);
							log.put(processId, imageLoadedList);
						}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	private String parseElement(String elem) {
		String elems[] = elem.split(": ");
		String value = elems[1].trim();
		return value;
	}

	private void outputLoadedDLLs(Map map, String outputFilename) {
		File file = new File(outputFilename);
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);

			for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
				Map.Entry<Integer, HashSet> entry = (Map.Entry<Integer, HashSet>) it.next();
				TreeSet<String> imageLoadedList = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
				imageLoadedList.addAll(entry.getValue());
				for (String value : imageLoadedList) {
					pw.println(value);
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

	private boolean compareResults(String masterFilename) {
		HashSet<String> masterList = new HashSet<String>();
		BufferedReader br = null;
		try {
			File f = new File(masterFilename);
			br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				String dll = line.trim();
				masterList.add(dll);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally{
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		boolean result = masterList.equals(this.imageLoadedList);
		System.out.println("Compare result:" + result);
		return result;
	}

	/**
	 * Parse CSV files exported from Sysmon event log. Output DLLs loaded by
	 * mimikatz in each environment.
	 * 
	 * @param inputDirname
	 * @param outputDirname
	 */
	public void outputDllsForEachEnvironment(String inputDirname, String outputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();
		for (File file : files) {
			String filename = file.getName();
			String outFilename = outputDirname + "/DLLlist_" + filename;
			if (filename.endsWith(".csv")) {
				// Read input CSV files and parse DLLs
				readCSV(file.getAbsolutePath());
				// Output loaded Dlls in each environment
				outputLoadedDLLs(log, outFilename);
				log.clear();
			}
		}
	}

	private void outputDlls(Collection c, String outfilename) {
		TreeSet<String> dlls = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
		dlls.addAll(c);
		File file = new File(outfilename);
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			for (String dll : dlls) {
				pw.println(dll);
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

	/**
	 * Create Common DLL list. Output DLLs loaded by mimikatz for all
	 * environment. Create Common DLL List.
	 * 
	 * @param outputDirname
	 */
	public void outputAllResults(String outputDirname) {
		Map<String, TreeSet<String>> dllMap = new HashMap<String, TreeSet<String>>();
		BufferedReader br = null;
		try {
			// Read DLL lists for each environment
			File dir = new File(outputDirname);
			File[] files = dir.listFiles();
			for (File file : files) {
				String filename = file.getName();
				if (!filename.endsWith(".csv")) {
					continue;
				}
				TreeSet<String> dlls = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
				br = new BufferedReader(new FileReader(file));
				String line;
				while ((line = br.readLine()) != null) {
					String[] data = line.split(",");
					if (data.length > 0) {
						String dll = data[0];
						dlls.add(dll);
					}
				}
				// Use file name as environment name. The name is printed in
				// result file to identify each environment
				String[] filenameArray = filename.split("\\.");
				String envName = filenameArray[0];
				dllMap.put(envName, dlls);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		// intersection of DLL lists(=Common DLL list)
		Collection intersection = null;
		// union of DLL lists
		Collection union = null;
		for (Iterator it = dllMap.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Integer, TreeSet> entry = (Map.Entry<Integer, TreeSet>) it.next();
			TreeSet<String> dlls = entry.getValue();
			if (null == intersection || intersection.size() == 0) {
				intersection = dlls;
			}
			if (null == union || union.size() == 0) {
				union = dlls;
			}
			intersection = CollectionUtils.intersection(intersection, dlls);
			union = CollectionUtils.union(union, dlls);
		}
		// Create Common DLL list
		outputDlls(intersection, outputDirname + "/CommonDLLlist.csv");
		TreeSet<String> unionDlls = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
		unionDlls.addAll(union);

		// Output DLL lists for all environment
		File file = new File(outputDirname + "/AllDLLs.csv");
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			for (Iterator it = dllMap.entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).iterator(); it
					.hasNext();) {
				Map.Entry<Integer, TreeSet> entry = (Map.Entry<Integer, TreeSet>) it.next();
				Object envName = entry.getKey();
				pw.print("," + envName);
			}
			pw.println();
			for (String dll : unionDlls) {
				pw.print(dll + ",");
				for (Iterator it = dllMap.entrySet().stream().sorted(java.util.Map.Entry.comparingByKey())
						.iterator(); it.hasNext();) {
					Map.Entry<Integer, TreeSet> entry = (Map.Entry<Integer, TreeSet>) it.next();
					TreeSet<String> eachDlls = entry.getValue();
					if (eachDlls.contains(dll)) {
						pw.print(dll + ",");
					} else {
						pw.print("-,");
					}
				}
				pw.println();
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

	/**
	 * Delete All previous files in outDirname
	 */
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
		System.out.println("-d {inputdirpath} {outputdirpath}");
	}

	public static void main(String args[]) {
		String masterFilename = null;
		String outputFilename = null;
		String outDirname = null;
		SysmonParser sysmonParser = new SysmonParser();
		if (args.length < 2) {
			printUseage();
		} else if (args[0].startsWith("-d")) {
			// Process all files specified by -d directory.
			String inputDirname = args[1];
			if (args.length > 1) {
				// Output result files in specified directory.
				outDirname = args[2];
				sysmonParser.detelePrevFiles(outDirname);
				sysmonParser.outputDllsForEachEnvironment(inputDirname, outDirname);
				sysmonParser.outputAllResults(outDirname);
				System.out.println("Output DLL lists and Common DLL list in " + outDirname);
			}
		} else {
			// Process single file
			String filename = args[0];
			if (args.length > 1) {
				// result file
				outputFilename = args[1];
			}
			if (args.length > 2) {
				// compare result with specified file
				masterFilename = args[2];
			}
			sysmonParser.readCSV(filename);
			sysmonParser.outputLoadedDLLs(log, outputFilename);
			if (null != masterFilename) {
				sysmonParser.compareResults(masterFilename);
			}
		}
	}
}
