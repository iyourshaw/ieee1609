
function Init
		()
{
	var listElement = document.getElementsByTagName("A");
	var i;

	for(i = 1; i <= listElement.length; i ++)
		listElement[i - 1].setAttribute("onclick", "EVD(this)");
	
	listElement = document.getElementsByTagName("SPAN");

	for(i = 1; i <= listElement.length; i++)
	{
		if(listElement[i - 1].getAttribute("CLASS") == "EC")
			listElement[i - 1].setAttribute("onclick", "EC(this)");
	}
}

function EVD  //ensure visibility of the destination of a link
		(a_element)
{
	var strHref = a_element.getAttribute("HREF");
	var strId = strHref.substr(strHref.indexOf('#') + 1);
	var element = document.getElementById(strId);
	
	var yElementBefore = a_element.offsetTop;
	var yScrollBefore = window.scrollY;
	
	while(element.parentElement != null)
	{
		element = element.parentElement;

		if(element.getAttribute("CLASS") == "details")
			element.setAttribute("data-open", "");
	}

	var yElementAfter = a_element.offsetTop;
	
	if(yElementAfter > yElementBefore)
		window.scroll(0, yScrollBefore + yElementAfter - yElementBefore);
}

function EC  //expand or collapse (toggle)
		(a_element)
{
	var element = a_element;

	while(element.parentElement != null)
	{
		element = element.parentElement;

		if(element.getAttribute("CLASS") == "details")
			break;
	}

	if(element.parentElement != null)	
	{	
		if(element.getAttribute("data-open") == null)
			element.setAttribute("data-open", "");
		else
			element.removeAttribute("data-open");
	}
}

function ECD  //expand or collapse descendants
		(a_element,
		 a_bExpand)
{
	var element = a_element;

	while(element.parentElement != null)
	{
		element = element.parentElement;

		if(element.getAttribute("CLASS") == "details")
			break;
	}

	if(element.parentElement != null)	
	{	
		if(a_bExpand)
			element.setAttribute("data-open", "");
		else
			element.removeAttribute("data-open");

		var listElement = element.getElementsByTagName("DIV");
		var i;

		for(i = 1; i <= listElement.length; i++)
		{
			if(listElement[i - 1].getAttribute("CLASS") == "details")
			{
				if(a_bExpand)
					listElement[i - 1].setAttribute("data-open", "");
				else
					listElement[i - 1].removeAttribute("data-open");
			}
		}
	}
}

