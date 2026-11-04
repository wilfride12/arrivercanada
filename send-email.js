'use strict';
/* Ancienne fonction d'envoi d'e-mail : elle permettait à n'importe qui d'envoyer des messages depuis votre adresse.
   Elle est désactivée. Les e-mails partent maintenant uniquement depuis le serveur (inscription, mot de passe oublié). */
exports.handler = async () => ({ statusCode: 410, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Fonction retirée.' }) });
