// WARNING
//
// This file has been generated automatically by Xamarin Studio to store outlets and
// actions made in the UI designer. If it is removed, they will be lost.
// Manual changes to this file may not be handled correctly.
//
using Foundation;
using System.CodeDom.Compiler;

namespace RestSsoAdminSnapIn
{
	[Register ("AddNewServiceEndpointController")]
	partial class AddNewServiceEndpointController
	{
		[Outlet]
		AppKit.NSButton BtnAdd { get; set; }

		[Outlet]
		AppKit.NSButton BtnClose { get; set; }

		[Outlet]
		AppKit.NSTextField TxtBinding { get; set; }

		[Outlet]
		AppKit.NSTextField TxtEndpoint { get; set; }

		[Outlet]
		AppKit.NSTextField TxtName { get; set; }
		
		void ReleaseDesignerOutlets ()
		{
			if (TxtName != null) {
				TxtName.Dispose ();
				TxtName = null;
			}

			if (TxtEndpoint != null) {
				TxtEndpoint.Dispose ();
				TxtEndpoint = null;
			}

			if (TxtBinding != null) {
				TxtBinding.Dispose ();
				TxtBinding = null;
			}

			if (BtnAdd != null) {
				BtnAdd.Dispose ();
				BtnAdd = null;
			}

			if (BtnClose != null) {
				BtnClose.Dispose ();
				BtnClose = null;
			}
		}
	}
}
