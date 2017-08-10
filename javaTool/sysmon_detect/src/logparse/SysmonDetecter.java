package logparse;
import java.io.*;
import java.util.*;
import org.apache.commons.collections4.*;
import org.apache.commons.lang3.ArrayUtils;

public class SysmonDetecter {
	
	private static final String MIMILATZ_MODULE_NAME="mimikatz.exe";
	private  static Map<Integer,HashSet> log;
	private  static Map<Integer,HashSet> image;
	private static HashSet<String> masterList=new HashSet<String>();
	private static String masterFilename=null;
	private static String outputDirName=null;
	private static int falsePositiveCnt=0;
	private static int falseNegativeCnt=0;

	public void readCSV(String filename){

		 	log=new HashMap<Integer,HashSet>();
		 	image=new HashMap<Integer,HashSet>();
		 	
		    try {
		      File f = new File(filename);
		      BufferedReader br = new BufferedReader(new FileReader(f));
		      String line;
		      int processId=0;
		      
		      while ((line = br.readLine()) != null) {
		        String[] data = line.split(",", 0); 
		        
		        for (String elem : data) {
		        	
		        	if(elem.startsWith("ProcessId:")) {
		        		processId=Integer.parseInt(parseElement(elem));
		        	}
		        	else if(elem.startsWith("Image:")) {
		        		HashSet<String> images=image.get(processId);
		        		if(null==images){
		        			images=new HashSet<String>();
		        		}
		        		images.add(parseElement(elem));
		        		image.put(processId, images);
		        	}
		        	else if(elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
		        		String imageLoaded=parseElement(elem);
		        		
		        		HashSet<String> imageLoadedList;
		        		if(null==log.get(processId)){
		        			imageLoadedList=new HashSet<String>();
		        		} else{
		        			imageLoadedList=log.get(processId);
		        		}
		        		imageLoadedList.add(imageLoaded);
			        	log.put(processId,imageLoadedList);
		        		}
		       
		        	}
		      }
		      br.close();

		    } catch (IOException e) {
		      System.out.println(e);
		    }
		
	}
	
	public String parseElement(String elem){
		String elems[]=elem.split(": ");
		String value=elems[1].trim();
		return value;
	}
	
	public void outputLoadedDLLs(Map map, String outputDirName){
		File file = new File(outputDirName);
		FileWriter filewriter=null;
		BufferedWriter bw = null;
		PrintWriter pw=null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
		
		for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
		    Map.Entry<Integer,HashSet> entry = (Map.Entry<Integer,HashSet>)it.next();
		    Object key = entry.getKey();
		    HashSet<String> imageLoadedList= (HashSet<String>)entry.getValue();
		    boolean result=compareResults(masterFilename,imageLoadedList);
		    for (String value : imageLoadedList){
		    	HashSet<String> images=image.get(key);
		    	for (String image: images){
		    		//System.out.println(key+","+value+", "+image+", "+result);
		    		pw.println(key+","+value+", "+image+", "+result);
		    	}
		    }
		    HashSet<String> images=image.get(key);
		    boolean containsMimikatz=false;
	    	for (String image: images){
	    		if(image.endsWith(MIMILATZ_MODULE_NAME)){
	    			containsMimikatz=true;
	    			break;
	    		}
	    	}
		    if(result){
		    	if(!containsMimikatz){
		    		falsePositiveCnt++;
		    	}
		    } else{
		    	if(containsMimikatz){
		    		falseNegativeCnt++;
		    	}
		    }
		}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally{
		pw.close();
		try {
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		}
	}
	
	public boolean compareResults(String masterFilename,HashSet<String> imageLoadedList){
	    boolean result=imageLoadedList.containsAll(masterList);
		return result;
	}
	
	public void outputDetectedDlls(String dirname){
		File dir=new File(dirname);
		File[] files = dir.listFiles();
		
		for (File file: files){
			String filename=file.getName();
			if(filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
				outputLoadedDLLs(log,this.outputDirName+"/"+filename);
			} else{
				continue;
			}
		}
		
	}
	public void outputDetectionRate(){
		 File file = new File(outputDirName);
			FileWriter filewriter=null;
			BufferedWriter bw = null;
			PrintWriter pw=null;

		 int totalProcessCnt=log.size();
		 double falsePositiveRate=(double)falsePositiveCnt/totalProcessCnt;
		 double falseNegativeRate=(double)falseNegativeCnt/totalProcessCnt;
		 String falsePositiveRateS = String.format("%.2f", falsePositiveRate);
		 String falseNegativeRateS = String.format("%.2f", falseNegativeRate);
			try {
				filewriter = new FileWriter(this.outputDirName+"/"+"detectionRate.txt");
				bw = new BufferedWriter(filewriter);
				pw = new PrintWriter(bw);
				pw.println("Total process count: "+totalProcessCnt);
				pw.println("False Positive count: "+falsePositiveCnt+", False Positive rate: "+falsePositiveRateS);
				pw.println("False Negative count: "+falseNegativeCnt+", False Negative rate: "+falseNegativeRateS);
			 } catch (IOException e) {
			      e.printStackTrace();
			 }
			finally{
				pw.close();
				try {
					bw.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		 System.out.println("Total process count: "+totalProcessCnt);
		 System.out.println("False Positive count: "+falsePositiveCnt+", False Positive rate: "+falsePositiveRateS);
		 System.out.println("False Negative count: "+falseNegativeCnt+", False Negative rate: "+falseNegativeRateS);
	}
	 public static void main(String args[]) {
		 
		 SysmonDetecter sysmonParser=new SysmonDetecter();
		 
			 String dirname=args[0];
			 
			 if(args.length>1){
				 masterFilename=args[1];
			 }
				
			 if(args.length>2){
				 outputDirName=args[2];
			 }
			    try {
				      File f = new File(masterFilename);
				      BufferedReader br = new BufferedReader(new FileReader(f));
				      String line;
				      while ((line = br.readLine()) != null) {
				    	  String dll=line.trim();
				    	  masterList.add(dll);
				      }
			    } catch (IOException e) {
				      System.out.println(e);
				    }
			    
			 sysmonParser.outputDetectedDlls(dirname);
			 sysmonParser.outputDetectionRate();
			 
	 }

}
