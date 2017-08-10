package logparse;

import java.util.HashSet;

public class TestHashSet {
	public static void main (String args[]) {
		HashSet<String> imageLoadedList= new HashSet<String>();
		imageLoadedList.add("C:\\Windows\\System3\\thumbcache.dll");
		imageLoadedList.add("C:\\Windows\\System32\\mssprxy.dll");
		imageLoadedList.add("C:\\Windows\\System32\\StructuredQuery.dll");
		
		HashSet<String> masterList= new HashSet<String>();
		
		imageLoadedList.add("C:\\Windows\\System32\\mssprxy.dll");
		imageLoadedList.add("C:\\Windows\\System3\\thumbcache.dll");
		
		boolean result=imageLoadedList.containsAll(masterList);
	   
	    	System.out.println(result);
		
		
	}

}
