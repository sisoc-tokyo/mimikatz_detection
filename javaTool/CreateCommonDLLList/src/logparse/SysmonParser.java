package logparse;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.collections4.*;
import org.apache.commons.lang3.ArrayUtils;

public class SysmonParser {
	
	private  static Map<Integer,HashSet> log;
	private static final String MIMILATZ_MODULE_NAME="mimikatz.exe";
	HashSet<String> imageLoadedList;
	HashSet<String> prevImageLoadedList;
	
	public void readCSV(String filename){

		 	log=new HashMap<Integer,HashSet>();
		 	
		    try {
		      File f = new File(filename);
		      BufferedReader br = new BufferedReader(new FileReader(f));
		      String line;
		      int processId=0;
		      String image="";
		      
		      while ((line = br.readLine()) != null) {
		        String[] data = line.split(",", 0); 
		        
		        for (String elem : data) {
		        	
		        	if(elem.startsWith("ProcessId:")) {
		        		processId=Integer.parseInt(parseElement(elem));
		        	}
		        	else if(elem.startsWith("Image:")) {
		        		image=parseElement(elem);
		        	}
		        	else if(elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
		        		String imageLoaded=parseElement(elem);
		        		if(image.contains(MIMILATZ_MODULE_NAME)){
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
		      }
		      br.close();

		    } catch (IOException e) {
		      e.printStackTrace();
		    }
		
	}
	
	public String parseElement(String elem){
		String elems[]=elem.split(": ");
		String value=elems[1].trim();
		return value;
	}
	
	public void outputLoadedDLLs(Map map, String outputFilename){
		File file = new File(outputFilename);
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
		    TreeSet<String> imageLoadedList= new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
		    imageLoadedList.addAll(entry.getValue());
		    for (String value : imageLoadedList){
		    	//System.out.println(key+","+value);
		    	pw.println(value);
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
	
	public boolean compareResults(String masterFilename){
		HashSet<String> masterList=new HashSet<String>();
	    try {
		      File f = new File(masterFilename);
		      BufferedReader br = new BufferedReader(new FileReader(f));
		      String line;
		      while ((line = br.readLine()) != null) {
		    	  String dll=line.trim();
		    	  masterList.add(dll);
		      }
	    } catch (IOException e) {
		      e.printStackTrace();
		    }
	    
	    boolean result=masterList.equals(this.imageLoadedList);
	    System.out.println("Compare result:"+result);
		return result;
	}
	
	public void outputDetectedDlls(String dirname, String outDirname){
		File dir=new File(dirname);
		File[] files = dir.listFiles();
		// intersection
		Collection intersection=null;
		for (File file: files){
			String filename=file.getName();
			String outFilename=outDirname+"/result_"+filename;
			if(filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
				outputLoadedDLLs(log,outFilename);
				log.clear();
			} 
		}
	}
	public void outputDlls(Collection c, String outfilename) {
		TreeSet<String> dlls= new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
		dlls.addAll(c);
		File file = new File(outfilename);
		FileWriter filewriter=null;
		BufferedWriter bw = null;
		PrintWriter pw=null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			for(String dll:dlls){
				pw.println(dll);
			}
		 } catch (IOException e) {
		      e.printStackTrace();
		 }finally{
			 pw.close();
			 try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		 }
	}
	public void outputAllResults(String dirname) {
		Map<String,TreeSet<String>> dllMap=new HashMap<String,TreeSet<String>>();
		
	    try {
			File dir=new File(dirname);
			File[] files = dir.listFiles();
			
			for (File file: files){
				String filename=file.getName();
				if(!filename.endsWith(".csv")) {
					continue;
				}
				TreeSet<String> dlls= new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
			      BufferedReader br = new BufferedReader(new FileReader(file));
			      String line;
			      
			      while ((line = br.readLine()) != null) {
			        String[] data = line.split(","); 
			        if(data.length>0){
			        	String dll=data[0];
			        	dlls.add(dll);
			        }
			      }
			      br.close();
			      String[] filenamea=filename.split("\\.");
			      String envName=filenamea[0];
			      dllMap.put(envName, dlls);
		    } 
	    }catch (IOException e) {
		      e.printStackTrace();
		}
	    Collection intersection=null ;
	    Collection union=null ;
	    for (Iterator it = dllMap.entrySet().iterator(); it.hasNext();) {
		    Map.Entry<Integer,TreeSet> entry = (Map.Entry<Integer,TreeSet>)it.next();
		    Object key = entry.getKey();
		    //System.out.println(key);
		    TreeSet<String> dlls = entry.getValue();
		    for(String dll:dlls) {
		    	//System.out.println(dll);
		    }
		    if(null==intersection || intersection.size()==0){
		    	intersection =dlls;
		    }
		    if(null==union || union.size()==0){
		    	union =dlls;
		    }
		    intersection = CollectionUtils.intersection(intersection, dlls);
		    union = CollectionUtils.union(union, dlls);
	    }
	    outputDlls(intersection,dirname+"/dlllist.csv");
	    TreeSet<String> unionDlls= new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
	    unionDlls.addAll(union);
	    
		File file = new File(dirname+"/allresults.csv");
		FileWriter filewriter=null;
		BufferedWriter bw = null;
		PrintWriter pw=null;
		try {
			filewriter = new FileWriter(file);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			
		    //for (Iterator it = dllMap.entrySet().iterator(); it.hasNext();) {
			for (Iterator it = dllMap.entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).iterator(); it.hasNext();) {
			    Map.Entry<Integer,TreeSet> entry = (Map.Entry<Integer,TreeSet>)it.next();
			    Object envName = entry.getKey();
			    pw.print(","+envName);
		    }
		    pw.println();
		    for(String dll:unionDlls) {
		    	pw.print(dll+",");
		    	for (Iterator it = dllMap.entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).iterator(); it.hasNext();) {
				    Map.Entry<Integer,TreeSet> entry = (Map.Entry<Integer,TreeSet>)it.next();
				    TreeSet<String> eachDlls = entry.getValue();
				    if(eachDlls.contains(dll)){
				    	pw.print(dll+",");
				    }else{
				    	pw.print("-,");
				    }
			    }
		    	pw.println();
		    }
		 }catch (IOException e) {
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
	public void detelePrevFiles(String outDirname){
		Path path = Paths.get(outDirname);
		try(DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*") ){
		    for(Path deleteFilePath : ds){
		             Files.delete(deleteFilePath);
		    }
		} catch (IOException e) {
		    e.printStackTrace();
		}
	}
	
	 public static void main(String args[]) {
		 String masterFilename=null;
		 String outputFilename=null;
		 String outDirname=null;
		 SysmonParser sysmonParser=new SysmonParser();
		 if(args.length==0){
			 System.out.println("Useage");
			 System.out.println("-d directory path");
		 }
		 else if(args[0].startsWith("-d")) {
			 // Process all files specified by -d directory.
			 String dirname=args[1];
			 if(args.length>1){
				 // result dir
				 outDirname=args[2];
			 }
			 sysmonParser.detelePrevFiles(outDirname);
			 sysmonParser.outputDetectedDlls(dirname,outDirname);
			 sysmonParser.outputAllResults(outDirname);
		 }else {
			 // Process a file
			 String filename=args[0];
			 if(args.length>1){
				 // result file
				 outputFilename=args[1];
			 }
			 if(args.length>2){
				 // compare result with specified file
				 masterFilename=args[2];
			 }
			 sysmonParser.readCSV(filename);
			 sysmonParser.outputLoadedDLLs(log,outputFilename);
			 if(null!=masterFilename){
				 sysmonParser.compareResults(masterFilename);
			 }
		 }
	 }

}
