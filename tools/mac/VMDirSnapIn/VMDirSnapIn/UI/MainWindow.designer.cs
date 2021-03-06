// WARNING
//
// This file has been generated automatically by Xamarin Studio to store outlets and
// actions made in the UI designer. If it is removed, they will be lost.
// Manual changes to this file may not be handled correctly.
//
using Foundation;
using System.CodeDom.Compiler;

namespace VMDirSnapIn.UI
{
	[Register ("MainWindowController")]
	partial class MainWindowController
	{
		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem AddGroupToolBarItem { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem AddObjectToolBarItem { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem AddUserToolBarItem { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem BackForwardToolBarItem { get; private set; }

		[Outlet]
		AppKit.NSMenuItem ConnectMenuItem { get; set; }

		[Outlet]
		public AppKit.NSView ContainerView { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem DeleteObjectToolBarItem { get; private set; }

		[Outlet]
		AppKit.NSMenuItem DisconnectMenuItem { get; set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem PropertiesToolBarItem { get; private set; }

		[Outlet]
		VmIdentity.UI.Common.ActivatableToolBarItem RefreshToolBarItem { get; set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem SchemaToolBarItem { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem SearchToolBarItem { get; private set; }

		[Outlet]
		public VmIdentity.UI.Common.ActivatableToolBarItem ServerToolBarItem { get; private set; }

		[Outlet]
		AppKit.NSTextField StatusLabel { get; set; }

		[Outlet]
		VmIdentity.UI.Common.ActivatableToolBarItem SuperLogToolBarItem { get; set; }

		[Action ("AddGroup:")]
		partial void AddGroup (Foundation.NSObject sender);

		[Action ("AddObject:")]
		partial void AddObject (Foundation.NSObject sender);

		[Action ("AddUser:")]
		partial void AddUser (Foundation.NSObject sender);

		[Action ("BackForwardAction:")]
		partial void BackForwardAction (Foundation.NSObject sender);

		[Action ("CloseConnection:")]
		partial void CloseConnection (Foundation.NSObject sender);

		[Action ("CloseSheet:")]
		partial void CloseSheet (Foundation.NSObject sender);

		[Action ("ConnectServer:")]
		partial void ConnectServer (Foundation.NSObject sender);

		[Action ("DeleteObject:")]
		partial void DeleteObject (Foundation.NSObject sender);

		[Action ("HandleConnection:")]
		partial void HandleConnection (Foundation.NSObject sender);

		[Action ("OnRefresh:")]
		partial void OnRefresh (Foundation.NSObject sender);

		[Action ("ShowSchema:")]
		partial void ShowSchema (Foundation.NSObject sender);

		[Action ("ShowSuperLogWindow:")]
		partial void ShowSuperLogWindow (Foundation.NSObject sender);

		[Action ("StartSearch:")]
		partial void StartSearch (AppKit.NSSearchField sender);

		[Action ("ViewProperties:")]
		partial void ViewProperties (Foundation.NSObject sender);
		
		void ReleaseDesignerOutlets ()
		{
			if (AddGroupToolBarItem != null) {
				AddGroupToolBarItem.Dispose ();
				AddGroupToolBarItem = null;
			}

			if (AddObjectToolBarItem != null) {
				AddObjectToolBarItem.Dispose ();
				AddObjectToolBarItem = null;
			}

			if (AddUserToolBarItem != null) {
				AddUserToolBarItem.Dispose ();
				AddUserToolBarItem = null;
			}

			if (BackForwardToolBarItem != null) {
				BackForwardToolBarItem.Dispose ();
				BackForwardToolBarItem = null;
			}

			if (ConnectMenuItem != null) {
				ConnectMenuItem.Dispose ();
				ConnectMenuItem = null;
			}

			if (ContainerView != null) {
				ContainerView.Dispose ();
				ContainerView = null;
			}

			if (DeleteObjectToolBarItem != null) {
				DeleteObjectToolBarItem.Dispose ();
				DeleteObjectToolBarItem = null;
			}

			if (DisconnectMenuItem != null) {
				DisconnectMenuItem.Dispose ();
				DisconnectMenuItem = null;
			}

			if (PropertiesToolBarItem != null) {
				PropertiesToolBarItem.Dispose ();
				PropertiesToolBarItem = null;
			}

			if (RefreshToolBarItem != null) {
				RefreshToolBarItem.Dispose ();
				RefreshToolBarItem = null;
			}

			if (SchemaToolBarItem != null) {
				SchemaToolBarItem.Dispose ();
				SchemaToolBarItem = null;
			}

			if (SearchToolBarItem != null) {
				SearchToolBarItem.Dispose ();
				SearchToolBarItem = null;
			}

			if (SuperLogToolBarItem != null) {
				SuperLogToolBarItem.Dispose ();
				SuperLogToolBarItem = null;
			}

			if (ServerToolBarItem != null) {
				ServerToolBarItem.Dispose ();
				ServerToolBarItem = null;
			}

			if (StatusLabel != null) {
				StatusLabel.Dispose ();
				StatusLabel = null;
			}
		}
	}

	[Register ("MainWindow")]
	partial class MainWindow
	{
		
		void ReleaseDesignerOutlets ()
		{
		}
	}
}
