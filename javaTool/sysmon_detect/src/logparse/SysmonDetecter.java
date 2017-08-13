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
public class SysmonDetecter {

	 /**
	 * Specify file name of mimikatz
	 */
	private static final String MIMIKATZ_MODULE_NAME = "mimikatz.exe";
	private static Map<Integer, HashSet> log;
	private static Map<Integer, HashSet> image;
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

			while ((line = br.readLine()) != null) {
				String[] data = line.split(",", 0);

				for (String elem : data) {

					if (elem.startsWith("ProcessId:")) {
						processId = Integer.parseInt(parseElement(elem));
					} else if (elem.startsWith("Image:")) {
						HashSet<String> images = image.get(processId);
						if (null == images) {
							images = new HashSet<String>();
						}
						images.add(parseElement(elem));
						image.put(processId, images);
					} else if (elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
						String imageLoaded = parseElement(elem);

						HashSet<String> imageLoadedList;
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
			br.close();

		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem) {
		String elems[] = elem.split(": ");
		String value = elems[1].trim();
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
				HashSet<String> imageLoadedList = (HashSet<String>) entry.getValue();
				boolean result = isMatchWithCommonDLLlist(commonDLLlistFileName, imageLoadedList);
				for (String value : imageLoadedList) {
					HashSet<String> images = image.get(processId);
					for (String image : images) {
						pw.println(processId + "," + value + ", " + image + ", " + result);
					}
				}
				HashSet<String> images = image.get(processId);
				boolean containsMimikatz = false;
				for (String image : images) {
					if (image.endsWith(MIMIKATZ_MODULE_NAME)) {
						containsMimikatz = true;
						break;
					}
				}
				if (result) {
					System.out.println("Detected. filename:"+filename+", Process ID:"+processId);
					if (!containsMimikatz) {
						falsePositiveCnt++;
					}
				} else {
					if (containsMimikatz) {
						falseNegativeCnt++;
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
		boolean result = imageLoadedList.containsAll(commonDLLlist);
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

	/**
	* Evaluate detection rate using Common DLL List.
	*/
	public void outputDetectionRate() {
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;

		int totalProcessCnt = log.size();
		double falsePositiveRate = (double) falsePositiveCnt / totalProcessCnt;
		double falseNegativeRate = (double) falseNegativeCnt / totalProcessCnt;
		String falsePositiveRateS = String.format("%.2f", falsePositiveRate);
		String falseNegativeRateS = String.format("%.2f", falseNegativeRate);
		try {
			filewriter = new FileWriter(this.outputDirName + "/" + "detectionRate.txt");
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			pw.println("Total process count: " + totalProcessCnt);
			pw.println("False Positive count: " + falsePositiveCnt + ", False Positive rate: " + falsePositiveRateS);
			pw.println("False Negative count: " + falseNegativeCnt + ", False Negative rate: " + falseNegativeRateS);
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
		System.out.println("Total process count: " + totalProcessCnt);
		System.out
				.println("False Positive count: " + falsePositiveCnt + ", False Positive rate: " + falsePositiveRateS);
		System.out
				.println("False Negative count: " + falseNegativeCnt + ", False Negative rate: " + falseNegativeRateS);
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
		SysmonDetecter sysmonParser = new SysmonDetecter();
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
		image = new HashMap<Integer, HashSet>();
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.readCommonDLLList();
		sysmonParser.outputLoadedDlls(inputdirname);
		if (args.length > 3) {
			String option = args[3];
			if (option.equals("-dr")) {
				sysmonParser.outputDetectionRate();
			}
		}

	}

}
