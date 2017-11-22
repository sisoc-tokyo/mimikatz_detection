package logparse;

public class EventLogData {
	
	private String date="";
	private String image="";
	private String imageLoaded="";
	
	EventLogData(String date, String imageLoaded, String image){
		this.date=date;
		this.image=image;
		this.imageLoaded=imageLoaded;
	}
	
	public void setDate(String date){
		this.date=date;
	}
	
	public void setImage(String image){
		this.image=image;
	}
	
	public String getDate(){
		return this.date;
	}
	
	public String getImage(){
		return this.image;
	}
	public String getImageLoaded(){
		return this.imageLoaded;
	}

}
