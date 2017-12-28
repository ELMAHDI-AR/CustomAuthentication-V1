using CustomAuthenticationMVC.CustomAuthentication;
using CustomAuthenticationMVC.DataAccess;
using CustomAuthenticationMVC.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace CustomAuthenticationMVC.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Login(string ReturnUrl = "")
        {
            if (User.Identity.IsAuthenticated)
            {
                return LogOut();
            }
            ViewBag.ReturnUrl = ReturnUrl;
            return View();
        }

        [HttpPost]
        public ActionResult Login(LoginView loginView, string ReturnUrl = "")
        {
            if (ModelState.IsValid)
            {
                if (Membership.ValidateUser(loginView.UserName, loginView.Password))
                {
                    var user = (CustomMembershipUser)Membership.GetUser(loginView.UserName, false);
                    if (user != null)
                    {
                        CustomSerializeModel userModel = new Models.CustomSerializeModel()
                        {
                            UserId = user.UserId,
                            FirstName = user.FirstName,
                            LastName = user.LastName,
                            RoleName = user.Roles.Select(r => r.RoleName).ToList()
                        };

                        string userData = JsonConvert.SerializeObject(userModel);
                        FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket
                            (
                            1, loginView.UserName, DateTime.Now, DateTime.Now.AddMinutes(15), false, userData
                            );

                        string enTicket = FormsAuthentication.Encrypt(authTicket);
                        HttpCookie faCookie = new HttpCookie("Cookie1", enTicket);
                        Response.Cookies.Add(faCookie);
                    }

                    if (Url.IsLocalUrl(ReturnUrl))
                    {
                        return Redirect(ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index");
                    }
                }
            }
            ModelState.AddModelError("", "Incorrect username and / or password");
            return View(loginView);
        }

        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registration(RegistrationView registrationView)
        {
            bool status = false;
            string message = string.Empty;

            if(ModelState.IsValid)
            {
                // Email is already Exists
                string userName = Membership.GetUserNameByEmail(registrationView.Email);
                if (!string.IsNullOrEmpty(userName))
                {
                    ModelState.AddModelError("ErrorEmail", "Email already Exist");
                    return View(registrationView);
                }

                //Activation Code
                registrationView.ActivationCode = Guid.NewGuid();

                //Save Data to DataBase
                using (AuthenticationDB dbContext = new AuthenticationDB())
                {
                    var user = new User()
                    {
                        Username = registrationView.Username,
                        FirstName = registrationView.FirstName,
                        LastName = registrationView.LastName,
                        Email = registrationView.Email,
                        Password = registrationView.Password,
                        ActivationCode = registrationView.ActivationCode,
                    };

                    dbContext.Users.Add(user);
                    dbContext.SaveChanges();
                }

                //Sending Email to User
                VerificationEmail(registrationView.Email, registrationView.ActivationCode.ToString());
                message = "Registration successfully done. Account activation link" + "has been sent to your email :" + registrationView.Email;
                status = true;
            }
            else
            {
                message = "Invalid Request!";
            }
            ViewBag.Message = message;
            ViewBag.Status = status;

            return View(registrationView);
        }

        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool status = false;
            using (AuthenticationDB dbContext = new DataAccess.AuthenticationDB ())
            {
                var userAccount = dbContext.Users.Where(u => u.ActivationCode.ToString().Equals(id)).FirstOrDefault();
                
                if(userAccount != null)
                {
                    userAccount.IsActive = true;
                    dbContext.SaveChanges();
                    status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
                 
            }
            ViewBag.Status = status;
            return View();
        }

        public ActionResult LogOut()
        {
            HttpCookie cookie = new HttpCookie("Cookie1", "");
            cookie.Expires = DateTime.Now.AddYears(-1);
            Response.Cookies.Add(cookie);

            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "Account", null);
        }

        [NonAction]
        public void VerificationEmail(string email, string activationCode)
        {
            var url = "/Account/VerifyAccount/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, url);

            var fromEmail = new MailAddress("mehdi.rami2012@gmail.com", "Account Validation - AKKA");
            var toEmail = new MailAddress(email);

            var fromEmailPassword = "azerty123456789AA";
            string subject = "Your Account is successfully created!";

            string body = "<br/><br/> We are excited to tell you that your acount is successfully created. Please click on the below link to verify your account" + "<br/><br/><a href='" + link + "'>" + link + "</a>";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true

            })

            smtp.Send(message);

        }
    }
}