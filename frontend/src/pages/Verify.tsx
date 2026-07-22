/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useState } from "react";
import { apiEndpoint } from "../config";
import { useTranslation } from "react-i18next";

// Matches backend issuance payload in handleNextSession
export type Ticket = {
    firstname: string;
    lastname: string;
    flight: string;
    from: string;
    to: string;
    seat: string;
    date: string; // YYYY-M-D per backend; render as-is
    time: string; // HH:mm
    gate: string;
};

export default function Verify() {
    const { t, i18n } = useTranslation();
    const lang = ((i18n.resolvedLanguage || i18n.language || "en").slice(0, 2) === "nl" ? "nl" : "en") as
        | "nl"
        | "en";

    const [error, setError] = useState<string>("");
    const [sessionDone, setSessionDone] = useState(false);
    const [ticket, setTicket] = useState<Ticket | null>(null);

    useEffect(() => {
        let cancelled = false;
        let web: any;

        import("@privacybydesign/yivi-frontend")
            .then((yivi: any) => {
                if (cancelled) return;

                setSessionDone(false);
                setError("");
                setTicket(null);

                web = yivi.newWeb({
                    debugging: true,
                    element: "#yivi-web-form",
                    language: lang,
                    session: {
                        url: apiEndpoint,
                        start: {
                            url: (o: any) => `${o.url}/start`,
                            method: "GET",
                        },
                        result: {
                            // The backend returns an unpredictable lookup token from /start
                            // (mapped by yivi-frontend to sessionToken). It must be presented
                            // to /result, which is bound to it rather than to the sessionID.
                            url: (o: any, { sessionToken }: any) =>
                                `${o.url}/result?token=${encodeURIComponent(sessionToken ?? "")}`,
                            method: "GET",
                        },
                    },
                });

                web
                    .start()
                    .then((response: any) => {
                        // yivi-web resolves with whatever our result endpoint returned
                        // Our backend wraps IRMA server JSON as { sessionResult: <IRMA JSON> }
                        try {
                            const sessionResult =
                                response?.sessionResult ?? response; // be tolerant in case library passes through IRMA JSON directly

                            const parsedTicket = parseTicketFromSessionResult(sessionResult);
                            if (parsedTicket) {
                                setTicket(parsedTicket);
                            }
                            setSessionDone(true);
                        } catch (e) {
                            console.error(e);
                            setError(t("verify.error_parse") || "");
                        }
                    })
                    .catch((e: any) => {
                        console.error(e);
                        setError(t("verify.error_start"));
                    });
            })
            .catch((e: any) => {
                console.error(e);
                setError(t("verify.error_client"));
            });

        return () => {
            cancelled = true;
            web?.abort?.();
        };
    }, [lang, t]);

    return (
        <div
            className="card"
            style={{
                display: "grid",
                gap: "1rem",
                maxWidth: 820,
                margin: "0 auto",
                width: "100%",
                height: 680,
                overflow: "hidden",
            }}
        >
            <h2 style={{ marginTop: 0 }}>{t("verify.title")}</h2>

            <div style={{ display: "grid", gap: "1rem" }}>
                <div>
                    <BoardingPass ticket={ticket} ready={sessionDone} />
                </div>
                <div style={{ display: "grid", gap: "0.5rem", placeItems: "center" }}>
                    <p style={{ marginTop: 0, textAlign: "center" }}>
                        {t("verify.instructions")} {" "}
                        <a href="https://yivi.app/#download">https://yivi.app/#download</a>
                    </p>
                    <div id="yivi-web-form" />
                    {error && (
                        <div
                            style={{
                                color: "#b91c1c",
                                background: "#fef2f2",
                                border: "1px solid #fecaca",
                                padding: "0.75rem 1rem",
                                borderRadius: 8,
                            }}
                        >
                            <strong>{t("verify.error_label")}:</strong> {error}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function parseTicketFromSessionResult(sessionResult: any): Ticket | null {
    // sessionResult comes from IRMA server result API, or wrapped by our backend
    // Examples:
    // { "status":"DONE", "type":"disclosing", "disclosed":[ [ { rawvalue: "Alice", ...}, { rawvalue: "Smith", ...} ] ] }
    // Our backend's issuance uses values[0]=firstname, values[1]=lastname and then static flight data

    try {
        const disclosed = sessionResult?.disclosed as any[] | undefined;
        if (!Array.isArray(disclosed) || disclosed.length === 0) return null;

        const group = Array.isArray(disclosed[0]) ? (disclosed[0] as any[]) : [];

        const rawvalues: string[] = group
            .map((item: any) => (item && typeof item === "object" ? item.rawvalue : undefined))
            .filter((v: any) => typeof v === "string" && v.length > 0);

        const firstname = rawvalues[0] ?? "";
        const lastname = rawvalues[1] ?? "";

        // The rest comes from handleNextSession issuance payload
        return {
            firstname,
            lastname,
            flight: "Y256",
            from: "AMS",
            to: "MXP",
            seat: "15B",
            date: "2025-12-5",
            time: "13:30",
            gate: "12",
        };
    } catch (e) {
        console.error("Failed to parse sessionResult:", e, sessionResult);
        return null;
    }
}

function BoardingPass({ ticket, ready }: { ticket: Ticket | null; ready: boolean }) {
    const { t } = useTranslation();
    const name = ticket ? `${ticket.firstname} ${ticket.lastname}`.trim() : "—";
    const from = ticket?.from ?? "—";
    const to = ticket?.to ?? "—";
    const flight = ticket?.flight ?? "—";
    const seat = ticket?.seat ?? "—";
    const date = ticket?.date ?? "—";
    const time = ticket?.time ?? "—";
    const gate = ticket?.gate ?? "—";

    return (
        <div
            style={{
                borderRadius: 16,
                border: "1px solid #e5e7eb",
                background: "linear-gradient(135deg, #eff6ff, #ffffff)",
                color: "#111827",
                padding: "1rem",
            }}
        >
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 8,
                }}
            >
                <div style={{ fontWeight: 700 }}>{t("boardingpass.title")}</div>
                <div style={{ fontSize: 12, color: "#6b7280" }}>{t("boardingpass.subtitle")}</div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                <Field label={t("boardingpass.field_name")} value={name} />
                <Field label={t("boardingpass.field_flight")} value={flight} />
                <Field label={t("boardingpass.field_from")} value={from} />
                <Field label={t("boardingpass.field_to")} value={to} />
                <Field label={t("boardingpass.field_seat")} value={seat} />
                <Field label={t("boardingpass.field_gate")} value={gate} />
                <Field label={t("boardingpass.field_date")} value={date} />
                <Field label={t("boardingpass.field_time")} value={time} />
            </div>

            <div style={{ marginTop: 12, fontSize: 12, color: ready ? "#065f46" : "#92400e" }}>
                {ready ? t("boardingpass.ready") : t("boardingpass.pending")}
            </div>
        </div>
    );
}

function Field({ label, value }: { label: string; value: string }) {
    return (
        <div style={{ display: "grid", gap: 2 }}>
            <div
                style={{
                    fontSize: 10,
                    letterSpacing: 0.6,
                    textTransform: "uppercase",
                    color: "#6b7280",
                }}
            >
                {label}
            </div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>{value}</div>
        </div>
    );
}
