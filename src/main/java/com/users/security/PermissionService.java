package com.users.security;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.util.List;

import static com.users.security.Role.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.beans.User;
import com.users.repositories.ContactRepository;
import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepo;

	@Autowired
	private ContactRepository contactRepo;

	private UsernamePasswordAuthenticationToken getToken() {
		return (UsernamePasswordAuthenticationToken) getContext().getAuthentication();
	}

	// I'm pretty sure that is authenticating the role of whoever is using it.
	// So, if it detects an ADMIN, it will give them ADMIN access.
	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	// Maybe searching for users? That would be my guess by looking at this. It
	// will find the Id connected to the email.
	public long findCurrentUserId() {
		List<User> users = userRepo.findByEmail(getToken().getName());
		return users != null && !users.isEmpty() ? users.get(0).getId() : -1;
	}

	// This is saying that an ADMIN can edit USERS, but a USER can't edit
	// another USER
	public boolean canAccessUser(long userId) {
		return hasRole(ROLE_ADMIN) || (hasRole(USER_ADMIN) && findCurrentUserId() == userId);
	}

	// So, maybe this is finding all the users, but not the admins? I see that
	// if it doesen't equal a USER, it returns null.
	// I don't exactly know, though. This would be something to further look at,
	// or even ask about.
	public boolean canEditContact(long contactId) {
		return hasRole(USER_ADMIN) && contactRepo.findByUserIdAndId(findCurrentUserId(), contactId) != null;
	}

	public String getCurrentEmail() {
		return getToken().getName();
	}

	public User findCurrentUser() {
		List<User> users = userRepo.findByEmail(getToken().getName());
		return users != null && !users.isEmpty() ? users.get(0) : new User();
	}

}
