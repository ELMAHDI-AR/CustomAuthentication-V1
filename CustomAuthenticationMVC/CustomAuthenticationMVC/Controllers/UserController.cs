﻿using CustomAuthenticationMVC.CustomAuthentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CustomAuthenticationMVC.Controllers
{
    public class UserController : Controller
    {
        [CustomAuthorize(Roles ="User")]
        // GET: User
        public ActionResult Index()
        {
            return View();
        }
    }
}