@Controller
public class VulnClass {

    @RequestMapping(value = "/cookie1", method = "GET")
    public void badCookie1(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        response.addCookie(cookie);
    }


    @RequestMapping(value = "/cookie2", method = "GET")
    public void badCookie2(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }


    @RequestMapping(value = "/cookie3", method = "GET")
    public void badCookie3(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
    }


    @RequestMapping(value = "/cookie4", method = "GET")
    public void badCookie4(@RequestParam String value, HttpServletResponse response) {
       response.setHeader("Set-Cookie", "sessionID=123456789; SameSite=strict");
    }
  
  
  
    @RequestMapping(value = "/cookie5", method = "GET")
    public void badCookie5(@RequestParam String value, HttpServletResponse response) {
       response.setHeader("Set-Cookie", "sessionID=123456789; HttpOnly; SameSite=strict");
    }
    
    
    @RequestMapping(value = "/cookie6", method = "GET")
    public void badCookie6(@RequestParam String value, HttpServletResponse response) {
       response.setHeader("Set-Cookie", "sessionID=123456789; HttpOnly; SameSite=none; Secure");
    }
   

    @RequestMapping(value = "/cookie7", method = "GET")
    public void goodCookie1(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }


    @RequestMapping(value = "/cookie8", method = "GET")
    public void goodCookie2(@RequestParam String value, HttpServletResponse response) {
       response.setHeader("Set-Cookie", "sessionID=123456789; HttpOnly; Secure; SameSite=strict");
    }



   public Response goodCookie3(String cookie) {
     Cookie existingCookie = HttpRequest.getCookie(request.getCookies(), cookie);
     if (existingCookie != null) {
       existingCookie.setPath(Constant.cookiePath);
       existingCookie.setValue("");
       existingCookie.setMaxAge(0);
       existingCookie.setHttpOnly(true);
       existingCookie.setSecure(true);
       response.addCookie(existingCookie);
     }
     return this;
   }
  
}





// Spring Boot //////////////////////////////////////////////////////
@Configuration
public class SpringSessionConfiguration {
    @Bean
    public CookieSerializer badCookieSerializer1() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("JSESSIONID");
        serializer.setDomainName("localhost");
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(3600);
        serializer.setSameSite("Lax");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseSecureCookie(false);
        return serializer;
    }

    @Bean
    public CookieSerializer badCookieSerializer2() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("JSESSIONID");
        serializer.setDomainName("localhost");
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(3600);
        serializer.setSameSite("Strict");
        serializer.setUseHttpOnlyCookie(false);
        return serializer;
    }

    @Bean
    public CookieSerializer badCookieSerializer3() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("JSESSIONID");
        serializer.setDomainName("localhost");
        serializer.setCookiePath("/");
        serializer.setCookieMaxAge(3600);
        serializer.setSameSite("None");
        return serializer;
    }
 
}



@RestController
@RequestMapping("/test")
public class CookieController {

    @GetMapping(produces = "text/plain")
    public void badCookie1(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("myCookie", "myValue")
            .httpOnly(true)
            .secure(false)
            .maxAge(Duration.ofHours(1))
            .sameSite("Lax")
            .build()
            ;    
        // Set the cookie in response
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return
    }
    
    
    
    @GetMapping(produces = "text/plain")
    public void badCookie2(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("myCookie", "myValue")
            .httpOnly(false)
            .secure(true)
            .sameSite("Strict")
            .build()
            ;    
        // Set the cookie in response
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return
    }  
    
    
    
    @GetMapping(produces = "text/plain")
    public void badCookie3(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("myCookie", "myValue")
            .httpOnly(true)
            .secure(true)
            .sameSite("None")
            .build()
            ;
        // Set the cookie in response
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return
    }   
    
    
    private ResponseCookie maybeSessionCookie(ServerWebExchange exchange, String id, Duration maxAge) {
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(this.cookieName, id)
            .path(exchange.getRequest().getPath().contextPath().value() + "/")
            .maxAge(maxAge)
            .httpOnly(true)
            .secure("https".equalsIgnoreCase(exchange.getRequest().getURI().getScheme()))
            .sameSite("Lax");
        if (this.cookieInitializer != null) {
            this.cookieInitializer.accept(cookieBuilder);
        }
        return cookieBuilder.build();
    }
    
    
}
