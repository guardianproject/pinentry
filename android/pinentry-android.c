/* pinentry-curses.c - A secure curses dialog for PIN entry.
   Copyright (C) 2002 g10 Code GmbH
   
   This file is part of PINENTRY.
   
   PINENTRY is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   PINENTRY is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "pinentry.h"
#include "pinentry-curses.h"

int
android_cmd_handler (pinentry_t pe)
{
  /*if (pinentry->pin)
  {
    if (pe->error)
	pinentry.setError (from_utf8 (pe->error));
      if (pe->quality_bar)
	pinentry.setQualityBar (from_utf8 (pe->quality_bar));
      if (pe->quality_bar_tt)
	pinentry.setQualityBarTT (from_utf8 (pe->quality_bar_tt));
      int len = strlen (pin);
      if (len >= 0)
	{
	  pinentry_setbufferlen (pe, len + 1);
	  if (pe->pin)
	    {
	      strcpy (pe->pin, pin);
	      return len;
	    }
	}
  }*/
}

pinentry_cmd_handler_t pinentry_cmd_handler = android_cmd_handler;


int 
main (int argc, char *argv[])
{
  pinentry_init ("pinentry-android");

  /* Consumes all arguments.  */
  if (pinentry_parse_opts (argc, argv))
    {
      printf ("pinentry-android (pinentry) " VERSION "\n");
      exit (EXIT_SUCCESS);
    }

  if (pinentry_loop ())
    return 1;

  return 0;
}
