package com.users.beans;

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "emails")
public class Email {

	private String to;
	private String subject;
	private String message;
	private String custom;

	public Email() {

	}

	public Email(String to, String subject, String message, String custom) {
		this.to = to;
		this.subject = subject;
		this.message = message;
		this.custom = custom;
	}

	public String getTo() {
		return to;
	}

	public String getSubject() {
		return subject;
	}

	public String getMessage() {
		return message;
	}

	public String getCustom() {
		return custom;
	}

	public void setTo(String to) {
		this.to = to;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void setCustom(String custom) {
		this.custom = custom;
	}

}
