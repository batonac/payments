// Copyright (c) 2018, Frappe Technologies and contributors
// For license information, please see license.txt

frappe.ui.form.on("GoCardless Settings", {
  setup(frm) {
    frappe.realtime.on("gocardless_fetch_history_progress", (data) => {
      if (data.docname !== frm.doc.name) return;
      let percent = data.total ? (data.current * 100) / data.total : 100;
      frm.dashboard.show_progress(
        __("Fetching GoCardless History"),
        percent,
        __("Processed {0} of {1} events", [data.current, data.total]),
      );
    });

    frappe.realtime.on("gocardless_fetch_history_done", (data) => {
      if (data.docname !== frm.doc.name) return;
      frm.dashboard.hide_progress(__("Fetching GoCardless History"));
      frappe.show_alert({
        message: __("GoCardless history fetch complete ({0} events)", [
          data.total,
        ]),
        indicator: "green",
      });
    });
  },

  refresh(frm) {
    if (frm.is_new()) return;
    frm.add_custom_button(
      __("Fetch History"),
      () => {
        frappe.prompt(
          {
            fieldname: "days",
            label: __("Fetch history for the last (days)"),
            fieldtype: "Int",
            default: 30,
            reqd: 1,
          },
          (values) => {
            frm
              .call({
                method: "fetch_history",
                doc: frm.doc,
                args: { days: values.days },
                freeze: true,
                freeze_message: __("Starting…"),
              })
              .then((r) => {
                if (r.exc || !r.message) return;
                frappe.msgprint(
                  __(
                    "Fetching the last {0} days of GoCardless history in the background — progress will appear on this page.",
                    [r.message.days],
                  ),
                );
              });
          },
          __("Fetch GoCardless History"),
          __("Fetch"),
        );
      },
      __("Actions"),
    );
  },
});
