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
	[Register ("SchemaBrowserWindowController")]
	partial class SchemaBrowserWindowController
	{
		[Outlet]
		AppKit.NSButton CloseButton { get; set; }

		[Outlet]
		AppKit.NSTableView ContentRulesAuxTableView { get; set; }

		[Outlet]
		AppKit.NSTableView ContentRulesMayTableView { get; set; }

		[Outlet]
		AppKit.NSTableView ContentRulesMustTableView { get; set; }

		[Outlet]
		AppKit.NSTabView ContentRulesTabView { get; set; }

		[Outlet]
		AppKit.NSTableView ContentRulesView { get; set; }

		[Outlet]
		AppKit.NSOutlineView HierarchyOutlineView { get; set; }

		[Outlet]
		AppKit.NSTableView objectClassesList { get; set; }

		[Outlet]
		AppKit.NSTableView OptionalAttributesView { get; set; }

		[Outlet]
		AppKit.NSTableView RequiredAttributesView { get; set; }

		[Outlet]
		AppKit.NSTabView schemaTabView { get; set; }

		[Outlet]
		AppKit.NSTableView TabTableView { get; set; }
		
		void ReleaseDesignerOutlets ()
		{
			if (ContentRulesAuxTableView != null) {
				ContentRulesAuxTableView.Dispose ();
				ContentRulesAuxTableView = null;
			}

			if (ContentRulesMayTableView != null) {
				ContentRulesMayTableView.Dispose ();
				ContentRulesMayTableView = null;
			}

			if (ContentRulesMustTableView != null) {
				ContentRulesMustTableView.Dispose ();
				ContentRulesMustTableView = null;
			}

			if (ContentRulesTabView != null) {
				ContentRulesTabView.Dispose ();
				ContentRulesTabView = null;
			}

			if (ContentRulesView != null) {
				ContentRulesView.Dispose ();
				ContentRulesView = null;
			}

			if (HierarchyOutlineView != null) {
				HierarchyOutlineView.Dispose ();
				HierarchyOutlineView = null;
			}

			if (objectClassesList != null) {
				objectClassesList.Dispose ();
				objectClassesList = null;
			}

			if (OptionalAttributesView != null) {
				OptionalAttributesView.Dispose ();
				OptionalAttributesView = null;
			}

			if (RequiredAttributesView != null) {
				RequiredAttributesView.Dispose ();
				RequiredAttributesView = null;
			}

			if (schemaTabView != null) {
				schemaTabView.Dispose ();
				schemaTabView = null;
			}

			if (TabTableView != null) {
				TabTableView.Dispose ();
				TabTableView = null;
			}

			if (CloseButton != null) {
				CloseButton.Dispose ();
				CloseButton = null;
			}
		}
	}

	[Register ("SchemaBrowserWindow")]
	partial class SchemaBrowserWindow
	{
		
		void ReleaseDesignerOutlets ()
		{
		}
	}
}
